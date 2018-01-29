import os
import binascii
import logging
from twisted.internet import defer, threads
from lbrynet.core.cryptoutils import get_lbry_hash_obj
from lbrynet.core.Error import InvalidStreamDescriptorError
from lbrynet.core.StreamDescriptor import PlainStreamDescriptorWriter, BlobStreamDescriptorWriter


log = logging.getLogger(__name__)


EncryptedFileStreamType = "lbryfile"


@defer.inlineCallbacks
def save_sd_info(blob_manager, sd_hash, sd_info):
    if not blob_manager.blobs.get(sd_hash) or not blob_manager.blobs[sd_hash].get_is_verified():
        descriptor_writer = BlobStreamDescriptorWriter(blob_manager)
        calculated_sd_hash = yield descriptor_writer.create_descriptor(sd_info)
        if calculated_sd_hash != sd_hash:
            raise InvalidStreamDescriptorError("%s does not match calculated %s" %
                                               (sd_hash, calculated_sd_hash))
    stream_hash = yield blob_manager.storage.get_stream_hash_for_sd_hash(sd_hash)
    if not stream_hash:
        log.info("Saving info for %s", str(sd_info['stream_name']))
        stream_name = sd_info['stream_name']
        key = sd_info['key']
        stream_hash = sd_info['stream_hash']
        stream_blobs = sd_info['blobs']
        suggested_file_name = sd_info['suggested_file_name']
        yield blob_manager.storage.add_known_blobs(stream_blobs)
        yield blob_manager.storage.store_stream(stream_hash, sd_hash, stream_name, key,
                                                suggested_file_name, stream_blobs)

    defer.returnValue(stream_hash)


def get_sd_info(storage, stream_hash, include_blobs):
    d = storage.get_stream_info(stream_hash)

    def format_info(stream_info):
        fields = {}
        fields['stream_type'] = EncryptedFileStreamType
        fields['stream_name'] = stream_info[1]
        fields['key'] = stream_info[0]
        fields['suggested_file_name'] = stream_info[2]
        fields['stream_hash'] = stream_hash

        def format_blobs(blobs):
            formatted_blobs = []
            for blob_info in blobs:
                blob = {}
                if blob_info.length != 0:
                    blob['blob_hash'] = str(blob_info.blob_hash)
                blob['blob_num'] = blob_info.blob_num
                blob['iv'] = str(blob_info.iv)
                blob['length'] = blob_info.length
                formatted_blobs.append(blob)
            fields['blobs'] = formatted_blobs
            return fields

        if include_blobs is True:
            d = storage.get_blobs_for_stream(stream_hash)
        else:
            d = defer.succeed([])
        d.addCallback(format_blobs)
        return d

    d.addCallback(format_info)
    return d


def create_plain_sd(storage, stream_hash, file_name, overwrite_existing=False):

    def _get_file_name():
        actual_file_name = file_name
        if os.path.exists(actual_file_name):
            ext_num = 1
            while os.path.exists(actual_file_name + "_" + str(ext_num)):
                ext_num += 1
            actual_file_name = actual_file_name + "_" + str(ext_num)
        return actual_file_name

    if overwrite_existing is False:
        d = threads.deferToThread(_get_file_name())
    else:
        d = defer.succeed(file_name)

    def do_create(file_name):
        descriptor_writer = PlainStreamDescriptorWriter(file_name)
        d = get_sd_info(storage, stream_hash, True)
        d.addCallback(descriptor_writer.create_descriptor)
        return d

    d.addCallback(do_create)
    return d


class EncryptedFileStreamDescriptorValidator(object):
    def __init__(self, raw_info):
        self.raw_info = raw_info

    def validate(self):
        log.debug("Trying to validate stream descriptor for %s", str(self.raw_info['stream_name']))
        try:
            hex_stream_name = self.raw_info['stream_name']
            key = self.raw_info['key']
            hex_suggested_file_name = self.raw_info['suggested_file_name']
            stream_hash = self.raw_info['stream_hash']
            blobs = self.raw_info['blobs']
        except KeyError as e:
            raise InvalidStreamDescriptorError("Missing '%s'" % (e.args[0]))
        for c in hex_suggested_file_name:
            if c not in '0123456789abcdef':
                raise InvalidStreamDescriptorError(
                    "Suggested file name is not a hex-encoded string")
        h = get_lbry_hash_obj()
        h.update(hex_stream_name)
        h.update(key)
        h.update(hex_suggested_file_name)

        def get_blob_hashsum(b):
            length = b['length']
            if length != 0:
                blob_hash = b['blob_hash']
            else:
                blob_hash = None
            blob_num = b['blob_num']
            iv = b['iv']
            blob_hashsum = get_lbry_hash_obj()
            if length != 0:
                blob_hashsum.update(blob_hash)
            blob_hashsum.update(str(blob_num))
            blob_hashsum.update(iv)
            blob_hashsum.update(str(length))
            return blob_hashsum.digest()

        blobs_hashsum = get_lbry_hash_obj()
        for blob in blobs:
            blobs_hashsum.update(get_blob_hashsum(blob))
        if blobs[-1]['length'] != 0:
            raise InvalidStreamDescriptorError("Does not end with a zero-length blob.")
        h.update(blobs_hashsum.digest())
        if h.hexdigest() != stream_hash:
            raise InvalidStreamDescriptorError("Stream hash does not match stream metadata")
        log.debug("It is validated")
        return defer.succeed(True)

    def info_to_show(self):
        info = []
        info.append(("stream_name", binascii.unhexlify(self.raw_info.get("stream_name"))))
        size_so_far = 0
        for blob_info in self.raw_info.get("blobs", []):
            size_so_far += int(blob_info['length'])
        info.append(("stream_size", str(self.get_length_of_stream())))
        suggested_file_name = self.raw_info.get("suggested_file_name", None)
        if suggested_file_name is not None:
            suggested_file_name = binascii.unhexlify(suggested_file_name)
        info.append(("suggested_file_name", suggested_file_name))
        return info

    def get_length_of_stream(self):
        size_so_far = 0
        for blob_info in self.raw_info.get("blobs", []):
            size_so_far += int(blob_info['length'])
        return size_so_far
