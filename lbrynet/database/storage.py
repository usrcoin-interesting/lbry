import logging
import os
import time
import sqlite3
from twisted.internet import defer, task, reactor
from twisted.enterprise import adbapi

from lbryschema.claim import ClaimDict
from lbryschema.decode import smart_decode
from lbrynet import conf
from lbrynet.cryptstream.CryptBlob import CryptBlobInfo

log = logging.getLogger(__name__)


def get_next_announce_time(hash_announcer, num_hashes_to_announce=1, min_reannounce_time=60*60,
                           single_announce_duration=5):
    """
    Hash reannounce time is set to current time + MIN_HASH_REANNOUNCE_TIME,
    unless we are announcing a lot of hashes at once which could cause the
    the announce queue to pile up.  To prevent pile up, reannounce
    only after a conservative estimate of when it will finish
    to announce all the hashes.

    Args:
        num_hashes_to_announce: number of hashes that will be added to the queue
    Returns:
        timestamp for next announce time
    """
    queue_size = hash_announcer.hash_queue_size() + num_hashes_to_announce
    reannounce = max(min_reannounce_time,
                     queue_size * single_announce_duration)
    return time.time() + reannounce


def rerun_if_locked(f):
    def rerun(err, *args, **kwargs):
        log.error("Failed to execute (%s): %s", err, args)
        if err.check(sqlite3.OperationalError) and err.value.message == "database is locked":
            log.warning("database was locked. rerunning %s with args %s, kwargs %s",
                        str(f), str(args), str(kwargs))
            return task.deferLater(reactor, 0, wrapper, *args, **kwargs)
        return err

    def wrapper(*args, **kwargs):
        d = f(*args, **kwargs)
        d.addErrback(rerun, *args, **kwargs)
        return d

    return wrapper


class SqliteConnection(adbapi.ConnectionPool):
    def __init__(self, db_path):
        adbapi.ConnectionPool.__init__(self, 'sqlite3', db_path, check_same_thread=False)

    @rerun_if_locked
    def runInteraction(self, interaction, *args, **kw):
        return adbapi.ConnectionPool.runInteraction(self, interaction, *args, **kw)


class SQLiteStorage(object):
    def __init__(self, db_dir):
        self.db_dir = db_dir
        self._db_path = os.path.join(db_dir, "lbrynet.sqlite")
        log.info("connecting to %s", self._db_path)
        self.db = SqliteConnection(self._db_path)

    def setup(self):
        def _create_tables(transaction):

            # create table if not exists support (
            #     support_outpoint text not null primary key,
            #     claim_id text not null,
            #     amount real not null,
            #     valid_at_height real not null
            # );

            transaction.executescript("""
            pragma foreign_keys=on;
            pragma journal_mode=WAL;
    
            create table if not exists blob (
                blob_hash char(96) primary key not null,
                blob_length integer not null,
                next_announce_time integer not null,
                should_announce integer not null default 0,
                status text not null
            );
            
            create table if not exists stream (
                stream_hash char(96) not null primary key,
                sd_hash char(96) not null,
                stream_key text not null,
                stream_name text not null,
                suggested_filename text not null,
                foreign key(sd_hash) references blob(blob_hash)
            );
            
            create table if not exists stream_blob (
                stream_hash char(96) not null,
                blob_hash char(96),
                position integer not null,
                iv char(32) not null,
                primary key (stream_hash, blob_hash),
                foreign key(stream_hash) references stream(stream_hash),
                foreign key (blob_hash) references blob(blob_hash)
            );
            
            create table if not exists claim (
                claim_outpoint text not null primary key,
                claim_id char(40) not null,
                claim_name text not null,
                amount real not null,
                height real not null,
                serialized_metadata blob not null,
                channel_claim_id text,
                address text not null,
                claim_sequence real not null
            );

            create table if not exists file (
                stream_hash text primary key not null,
                claim_outpoint text not null,
                file_name text not null,
                download_directory text not null,
                blob_data_rate real not null,
                status text not null,
                foreign key(stream_hash) references stream(stream_hash),
                foreign key(claim_outpoint) references claim(claim_outpoint)
            );
            """)

        return self.db.runInteraction(_create_tables)

    def stop(self):
        self.db.close()
        return defer.succeed(True)

    # # # # # # # # # blob functions # # # # # # # # #

    def add_completed_blob(self, blob_hash, length, next_announce_time, should_announce):
        log.info("Adding a completed blob. blob_hash=%s, length=%i", blob_hash, length)
        d = self.add_known_blob(blob_hash, length)
        d.addCallback(lambda _: self.set_blob_status(blob_hash, "finished"))
        d.addCallback(lambda _: self.set_should_announce(blob_hash, next_announce_time,
                                                         should_announce))
        d.addCallback(lambda _: self.db.runOperation("update blob set blob_length=? "
                                                     "where blob_hash=?",
                                                     (length, blob_hash)))
        return d

    def set_should_announce(self, blob_hash, next_announce_time, should_announce):
        should_announce = 1 if should_announce else 0
        return self.db.runOperation("update blob set next_announce_time=?, should_announce=? "
                                    "where blob_hash=?", (next_announce_time, should_announce,
                                                          blob_hash))

    def set_blob_status(self, blob_hash, status):
        return self.db.runOperation("update blob set status=? where blob_hash=?", (status,
                                                                                   blob_hash))

    def get_blob_status(self, blob_hash):
        d = self.db.runQuery("select status from blob where blob_hash=?", (blob_hash, ))
        d.addCallback(lambda r: None if not r else r[0][0])
        return d

    @defer.inlineCallbacks
    def add_known_blob(self, blob_hash, length):
        status = yield self.get_blob_status(blob_hash)
        if status is None:
            status = "pending"
            yield self.db.runOperation("insert into blob values (?, ?, ?, ?, ?)",
                                       (blob_hash, length, 0, 0, status))
        defer.returnValue(status)

    def should_announce(self, blob_hash):
        d = self.db.runQuery("select should_announce from blob where blob_hash=?", (blob_hash, ))
        d.addCallback(lambda r: None if not r else r[0][0])
        return d

    def count_should_announce_blobs(self):
        d = self.db.runQuery("select count(*) from blob where should_announce=1 "
                             "and status=?", ("finished", ))
        d.addCallback(lambda r: r[0][0])
        return d

    def get_all_should_announce_blobs(self):
        d = self.db.runQuery("select blob_hash from blob where should_announce=1 "
                             "and status=?", ("finished", ))
        d.addCallback(lambda r: [i[0] for i in r])
        return d

    def get_blobs_to_announce(self, hash_announcer):
        def get_and_update(transaction):
            timestamp = time.time()
            if conf.settings['announce_head_blobs_only']:
                r = transaction.execute("select blob_hash from blob "
                                        "where blob_hash is not null and should_announce=1 and "
                                        "next_announce_time<?", (timestamp,))
            else:
                r = transaction.execute("select blob_hash from blob "
                                        "where blob_hash is not null and next_announce_time<?",
                                        (timestamp,))

            blobs = [b for b, in r.fetchall()]
            next_announce_time = get_next_announce_time(hash_announcer, len(blobs))
            transaction.execute("update blob set next_announce_time=? where next_announce_time<?",
                                (next_announce_time, timestamp))
            log.debug("Got %s blobs to announce, next announce time is in %s seconds", len(blobs),
                      next_announce_time-time.time())
            return blobs

        return self.db.runInteraction(get_and_update)

    def delete_blobs_from_db(self, blob_hashes):
        def delete_blobs(transaction):
            for blob_hash in blob_hashes:
                transaction.execute("delete from blob where blob_hash=?;", (blob_hash,))
        return self.db.runInteraction(delete_blobs)

    def get_all_blob_hashes(self):
        d = self.db.runQuery("select blob_hash from blob")
        d.addCallback(lambda r: [x[0] for x in r])
        return d

    # # # # # # # # # stream blob functions # # # # # # # # #

    def add_blobs_to_stream(self, stream_hash, blob_infos):
        def _add_stream_blobs(transaction):
            for blob_info in blob_infos:
                transaction.execute("insert into stream_blob values (?, ?, ?, ?)",
                                    (stream_hash, blob_info.get('blob_hash', None),
                                     blob_info['blob_num'], blob_info['iv']))
        return self.db.runInteraction(_add_stream_blobs)

    @defer.inlineCallbacks
    def add_known_blobs(self, blob_infos):
        for blob_info in blob_infos:
            if blob_info.get('blob_hash') and blob_info['length']:
                yield self.add_known_blob(blob_info['blob_hash'], blob_info['length'])

    # # # # # # # # # stream functions # # # # # # # # #

    def store_stream(self, stream_hash, sd_hash, stream_name, stream_key, suggested_file_name,
                     stream_blob_infos):
        """
        Add a stream to the stream table

        :param stream_hash: hash of the assembled stream
        :param sd_hash: hash of the sd blob
        :param stream_key: blob decryption key
        :param stream_name: the name of the file the stream was generated from
        :param suggested_file_name: (str) suggested file name for stream
        :param stream_blob_infos: (list) of blob info dictionaries
        :return: (defer.Deferred)
        """

        def _store_stream(transaction):
            transaction.execute("insert into stream values (?, ?, ?, ?, ?);",
                                 (stream_hash, sd_hash, stream_key, stream_name,
                                  suggested_file_name))

            for blob_info in stream_blob_infos:
                transaction.execute("insert into stream_blob values (?, ?, ?, ?)",
                                    (stream_hash, blob_info.get('blob_hash', None),
                                     blob_info['blob_num'], blob_info['iv']))

        return self.db.runInteraction(_store_stream)

    @defer.inlineCallbacks
    def delete_stream(self, stream_hash):
        sd_hash = yield self.get_sd_blob_hash_for_stream(stream_hash)
        stream_blobs = yield self.get_blobs_for_stream(stream_hash)
        blob_hashes = [b.blob_hash for b in stream_blobs]

        def _delete_stream(transaction):
            transaction.execute("delete from file where stream_hash=? ", (stream_hash, ))
            transaction.execute("delete from stream_blob where stream_hash=?", (stream_hash, ))
            transaction.execute("delete from stream where stream_hash=? ", (stream_hash, ))
            transaction.execute("delete from blob where blob_hash=?", (sd_hash, ))
            for blob_hash in blob_hashes:
                transaction.execute("delete from blob where blob_hash=?;", (blob_hash, ))
        yield self.db.runInteraction(_delete_stream)

    def get_all_streams(self):
        d = self.db.runQuery("select stream_hash from stream")
        d.addCallback(lambda results: [r[0] for r in results])
        return d

    def get_stream_info(self, stream_hash):
        d = self.db.runQuery("select stream_key, stream_name, suggested_filename from stream "
                             "where stream_hash=?", (stream_hash, ))
        d.addCallback(lambda r: None if not r else r[0])
        return d

    def check_if_stream_exists(self, stream_hash):
        d = self.db.runQuery("select stream_hash from stream where stream_hash=?", (stream_hash, ))
        d.addCallback(lambda r: True if len(r) else False)
        return d

    def get_blob_num_by_hash(self, stream_hash, blob_hash):
        d = self.db.runQuery("select position from stream_blob "
                             "where stream_hash=? and blob_hash=?", (stream_hash, blob_hash))
        d.addCallback(lambda r: None if not r else r[0][0])
        return d

    def get_stream_blob_by_position(self, stream_hash, blob_num):
        d = self.db.runQuery("select blob_hash from stream_blob "
                             "where stream_hash=? and position=?", (stream_hash, blob_num))
        d.addCallback(lambda r: None if not r else r[0][0])
        return d

    def get_blobs_for_stream(self, stream_hash):
        def _get_blobs_for_stream(transaction):
            crypt_blob_infos = []
            stream_blobs = transaction.execute("select blob_hash, position, iv from stream_blob "
                                               "where stream_hash=?", (stream_hash, )).fetchall()
            if stream_blobs:
                for blob_hash, position, iv in stream_blobs:
                    if blob_hash is not None:
                        blob_length = transaction.execute("select blob_length from blob "
                                                          "where blob_hash=?",
                                                          (blob_hash,)).fetchone()
                        blob_length = 0 if not blob_length else blob_length[0]
                        crypt_blob_infos.append(CryptBlobInfo(blob_hash, position, blob_length, iv))
                    else:
                        crypt_blob_infos.append(CryptBlobInfo(None, position, 0, iv))
                crypt_blob_infos = sorted(crypt_blob_infos, key=lambda info: info.blob_num)
            return crypt_blob_infos
        return self.db.runInteraction(_get_blobs_for_stream)

    def get_stream_of_blob(self, blob_hash):
        d = self.db.runQuery("select stream_hash from stream_blob where blob_hash=?", (blob_hash,))
        d.addCallback(lambda r: None if not r else r[0][0])
        return d

    def get_sd_blob_hash_for_stream(self, stream_hash):
        d = self.db.runQuery("select sd_hash from stream where stream_hash=?", (stream_hash,))
        d.addCallback(lambda r: None if not r else r[0][0])
        return d

    def get_stream_hash_for_sd_hash(self, sd_blob_hash):
        d = self.db.runQuery("select stream_hash from stream where sd_hash = ?", (sd_blob_hash, ))
        d.addCallback(lambda r: None if not r else r[0][0])
        return d

    @defer.inlineCallbacks
    def get_all_stream_infos(self):
        def _get_all_stream_infos(transaction):
            file_infos = transaction.execute("select rowid, * from file").fetchall()
            file_dicts = {}
            for rowid, stream_hash, outpoint, file_name, \
                download_directory, data_rate, status in file_infos:
                stream_info = transaction.execute("select * from stream where stream_hash=?",
                                                  (stream_hash, )).fetchall()
                sd_hash, key, stream_name, suggested_file_name = stream_info

                file_dicts[stream_hash] = {
                    'rowid': rowid,
                    'stream_hash': stream_hash,
                    'outpoint': outpoint,
                    'blob_data_rate': data_rate,
                    'status': status,
                    'sd_hash': sd_hash,
                    'key': key,
                    'stream_name': stream_name,
                    'suggested_file_name': suggested_file_name
                }
            return file_dicts

        result = yield self.db.runInteraction(_get_all_stream_infos)
        defer.returnValue(result)

    # # # # # # # # # file stuff # # # # # # # # #

    def save_lbry_file(self, stream_hash, outpoint, file_name, download_directory,
                       data_payment_rate, status):
        def do_save(db_transaction):
            db_transaction.execute("insert into file values (?, ?, ?, ?, ?, ?)",
                                    (stream_hash, outpoint, file_name, download_directory,
                                     data_payment_rate, status))
            file_rowid = db_transaction.lastrowid
            return file_rowid
        return self.db.runInteraction(do_save)

    def get_all_lbry_files(self):
        d = self.db.runQuery("select rowid, * from file")
        return d

    def change_file_status(self, rowid, new_status):
        d = self.db.runQuery("update file set status=? where rowid=?", (new_status, rowid))
        d.addCallback(lambda _: new_status)
        return d

    def get_lbry_file_status(self, rowid):
        d = self.db.runQuery("select status from file where rowid = ?", (rowid,))
        d.addCallback(lambda r: (r[0][0] if len(r) else None))
        return d

    def get_rowid_for_stream_hash(self, stream_hash):
        d = self.db.runQuery("select rowid from file where stream_hash=?", (stream_hash, ))
        d.addCallback(lambda r: (r[0][0] if len(r) else None))
        return d

    # # # # # # # # # claim stuff # # # # # # # # #

    @defer.inlineCallbacks
    def save_claim(self, claim_info):
        outpoint = "%s:%i" % (claim_info['txid'], claim_info['nout'])
        claim_dict = smart_decode(claim_info['value'])

        def _save_claim(transaction):
            transaction.execute("insert into claim values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                (outpoint, claim_info['claim_id'], claim_info['name'],
                                 claim_info['amount'], claim_info['height'],
                                 claim_dict.serialized.encode('hex'), claim_dict.certificate_id,
                                 claim_info['address'], claim_info['claim_sequence']))

            if claim_info['supports']:
                valid_at_height = claim_info['valid_at_height']
                transaction.execute("delete * from support where claim_id=? and valid_at_height<=?",
                                    (claim_info['claim_id']), valid_at_height)
                for support in claim_info['supports']:
                    transaction.execute("insert into support values (?, ?, ?, ?)",
                                        ("%s:%i" % (claim_info['txid'], claim_info['nout']),
                                         claim_info['claim_id'], support['amount'],
                                         valid_at_height))

        yield self.db.runInteraction(_save_claim)

    @defer.inlineCallbacks
    def get_claim(self, claim_id):
        def _claim_response(outpoint, claim_id, name, amount, height, serialized, channel_id,
                           address,
                           claim_sequence):
            return {
                "name": name,
                "claim_id": claim_id,
                "address": address,
                "claim_sequence": claim_sequence,
                "value": ClaimDict.deserialize(serialized).claim_dict,
                "height": height,
                "amount": amount,
                "effective_amount": 0.0,
                "nout": int(outpoint.split(":")[1]),
                "txid": outpoint.split(":")[0]
            }

        def _get_claim(transaction):
            claim_info = transaction.execute("select * from claim "
                                             "where claim_id=? order by rowid desc", (claim_id, )
                                             ).fetchone()
            return _claim_response(*claim_info)

        result = yield self.db.runInteraction(_get_claim)
        defer.returnValue(result)
