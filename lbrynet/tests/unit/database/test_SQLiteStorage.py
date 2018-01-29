import shutil
import tempfile

from twisted.internet import defer
from twisted.trial import unittest

from lbrynet import conf
from lbrynet.database.storage import SQLiteStorage
from lbrynet.core.StreamDescriptor import StreamDescriptorIdentifier
from lbrynet.file_manager.EncryptedFileDownloader import ManagedEncryptedFileDownloader
from lbrynet.file_manager.EncryptedFileManager import EncryptedFileManager
from lbrynet.tests.util import random_lbry_hash


def blob_info_dict(blob_info):
    info = {
        "length": blob_info.length,
        "blob_num": blob_info.blob_num,
        "iv": blob_info.iv
    }
    if blob_info.length:
        info['blob_hash'] = blob_info.blob_hash
    return info


fake_claim_info = {
    'name': "test",
    'claim_id': 'deadbeef' * 5,
    'address': "bT6wc54qiUUYt34HQF9wnW8b2o2yQTXf2S",
    'claim_sequence': 1,
    'value': "7b226465736372697074696f6e223a202257686174206973204c4252593f20416e20696e74726f64756"
             "374696f6e207769746820416c6578205461626172726f6b222c20226c6963656e7365223a20224c4252"
             "5920696e63222c2022617574686f72223a202253616d75656c20427279616e222c20226c616e6775616"
             "765223a2022656e222c20227469746c65223a202257686174206973204c4252593f222c2022736f7572"
             "636573223a207b226c6272795f73645f68617368223a202264353136393234313135303032326639393"
             "66661376364366139613163343231393337323736613332373565623931323739306264303762613761"
             "65633166616335666434353433316432323662386662343032363931653739616562323462227d2c202"
             "2636f6e74656e742d74797065223a2022766964656f2f6d7034222c20227468756d626e61696c223a20"
             "2268747470733a2f2f73332e616d617a6f6e6177732e636f6d2f66696c65732e6c6272792e696f2f6c6"
             "f676f2e706e67227d".decode('hex'),
    'height': 10000,
    'amount': 1.0,
    'effective_amount': 1.0,
    'nout': 0,
    'txid': "deadbeef" * 8,
    'supports': []
}


class FakeAnnouncer(object):
    def __init__(self):
        self._queue_size = 0

    def hash_queue_size(self):
        return self._queue_size


class StorageTest(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        conf.initialize_settings()
        self.db_dir = tempfile.mkdtemp()
        self.storage = SQLiteStorage(self.db_dir)
        yield self.storage.setup()

    @defer.inlineCallbacks
    def tearDown(self):
        yield self.storage.stop()
        shutil.rmtree(self.db_dir)

    @defer.inlineCallbacks
    def store_fake_blob(self, blob_hash, blob_length=100, next_announce=0, should_announce=0):
        yield self.storage.add_completed_blob(blob_hash, blob_length, next_announce,
                                              should_announce)
        yield self.storage.set_blob_status(blob_hash, "finished")

    @defer.inlineCallbacks
    def store_fake_stream_blob(self, stream_hash, blob_hash, blob_num, length=100, iv="DEADBEEF"):
        blob_info = {
            'blob_hash': blob_hash, 'blob_num': blob_num, 'iv': iv
        }
        if length:
            blob_info['length'] = length
        yield self.storage.add_blobs_to_stream(stream_hash, [blob_info])

    @defer.inlineCallbacks
    def store_fake_stream(self, stream_hash, sd_hash, file_name="fake_file", key="DEADBEEF",
                          blobs=[]):
        yield self.storage.store_stream(stream_hash, sd_hash, file_name, key,
                                           file_name, blobs)

    @defer.inlineCallbacks
    def store_fake_file(self, stream_hash, outpoint, file_name, download_directory, blob_data_rate,
                                                           status):
        yield self.storage.save_lbry_file(stream_hash, outpoint, file_name, download_directory,
                                          blob_data_rate, status)


class TestSetup(StorageTest):
    @defer.inlineCallbacks
    def test_setup(self):
        files = yield self.storage.get_all_lbry_files()
        self.assertEqual(len(files), 0)
        blobs = yield self.storage.get_all_blob_hashes()
        self.assertEqual(len(blobs), 0)


class BlobStorageTests(StorageTest):
    @defer.inlineCallbacks
    def test_store_blob(self):
        blob_hash = random_lbry_hash()
        yield self.store_fake_blob(blob_hash)
        blob_hashes = yield self.storage.get_all_blob_hashes()
        self.assertEqual(blob_hashes, [blob_hash])

    @defer.inlineCallbacks
    def test_delete_blob(self):
        blob_hash = random_lbry_hash()
        yield self.store_fake_blob(blob_hash)
        blob_hashes = yield self.storage.get_all_blob_hashes()
        self.assertEqual(blob_hashes, [blob_hash])
        yield self.storage.delete_blobs_from_db(blob_hashes)
        blob_hashes = yield self.storage.get_all_blob_hashes()
        self.assertEqual(blob_hashes, [])


class StreamStorageTests(StorageTest):
    @defer.inlineCallbacks
    def test_store_stream(self, stream_hash=None):
        stream_hash = stream_hash or random_lbry_hash()
        sd_hash = random_lbry_hash()
        blob1 = random_lbry_hash()
        blob2 = random_lbry_hash()

        yield self.store_fake_blob(sd_hash)
        yield self.store_fake_blob(blob1)
        yield self.store_fake_blob(blob2)

        yield self.store_fake_stream(stream_hash, sd_hash)
        yield self.store_fake_stream_blob(stream_hash, blob1, 1)
        yield self.store_fake_stream_blob(stream_hash, blob2, 2)

        stream_blobs = yield self.storage.get_blobs_for_stream(stream_hash)
        stream_blob_hashes = [b.blob_hash for b in stream_blobs]
        self.assertListEqual(stream_blob_hashes, [blob1, blob2])

        blob_hashes = yield self.storage.get_all_blob_hashes()
        self.assertSetEqual(set(blob_hashes), {sd_hash, blob1, blob2})

        stream_blobs = yield self.storage.get_blobs_for_stream(stream_hash)
        stream_blob_hashes = [b.blob_hash for b in stream_blobs]
        self.assertListEqual(stream_blob_hashes, [blob1, blob2])

        yield self.storage.set_should_announce(sd_hash, 1, 1)
        yield self.storage.set_should_announce(blob1, 1, 1)

        should_announce_count = yield self.storage.count_should_announce_blobs()
        self.assertEqual(should_announce_count, 2)
        should_announce_hashes = yield self.storage.get_blobs_to_announce(FakeAnnouncer())
        self.assertSetEqual(set(should_announce_hashes), {sd_hash, blob1})

        stream_hashes = yield self.storage.get_all_streams()
        self.assertListEqual(stream_hashes, [stream_hash])

    @defer.inlineCallbacks
    def test_delete_stream(self):
        stream_hash = random_lbry_hash()
        yield self.test_store_stream(stream_hash)
        yield self.storage.delete_stream(stream_hash)
        stream_hashes = yield self.storage.get_all_streams()
        self.assertListEqual(stream_hashes, [])

        stream_blobs = yield self.storage.get_blobs_for_stream(stream_hash)
        self.assertListEqual(stream_blobs, [])
        blob_hashes = yield self.storage.get_all_blob_hashes()
        self.assertListEqual(blob_hashes, [])


class FileStorageTests(StorageTest):
    @defer.inlineCallbacks
    def test_store_file(self):
        class MocSession(object):
            pass

        session = MocSession()
        session.db_dir = self.db_dir
        session.storage = self.storage
        sd_identifier = StreamDescriptorIdentifier()
        download_directory = self.db_dir
        manager = EncryptedFileManager(session, sd_identifier, download_directory)
        out = yield manager.session.storage.get_all_lbry_files()
        self.assertEqual(len(out), 0)

        stream_hash = random_lbry_hash()
        sd_hash = random_lbry_hash()
        blob1 = random_lbry_hash()
        blob2 = random_lbry_hash()

        yield self.store_fake_blob(sd_hash)
        yield self.store_fake_blob(blob1)
        yield self.store_fake_blob(blob2)

        yield self.store_fake_stream(stream_hash, sd_hash)
        yield self.store_fake_stream_blob(stream_hash, blob1, 1)
        yield self.store_fake_stream_blob(stream_hash, blob2, 2)

        yield self.storage.save_claim(fake_claim_info)

        blob_data_rate = 0
        outpoint = "%s:%i" % ("deadbeef" * 8, 0)
        file_name = "test file"
        status = "stopped"

        out = yield manager.session.storage.save_lbry_file(stream_hash, outpoint, file_name,
                                                           download_directory, blob_data_rate,
                                                           status)
        rowid = yield manager.session.storage.get_rowid_for_stream_hash(stream_hash)
        self.assertEqual(out, rowid)

        files = yield manager.session.storage.get_all_lbry_files()
        self.assertEqual(1, len(files))

        status = yield manager.session.storage.get_lbry_file_status(rowid)
        self.assertEqual(status, ManagedEncryptedFileDownloader.STATUS_STOPPED)

        running = ManagedEncryptedFileDownloader.STATUS_RUNNING
        yield manager.session.storage.change_file_status(rowid, running)
        status = yield manager.session.storage.get_lbry_file_status(rowid)
        self.assertEqual(status, ManagedEncryptedFileDownloader.STATUS_RUNNING)
