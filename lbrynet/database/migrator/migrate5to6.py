import sqlite3
import os
import json
import logging
from lbryschema.decode import smart_decode
from lbrynet import conf
from lbrynet.database.storage import SQLiteStorage

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


default_download_directory = conf.default_download_dir


def run_operation(db):
    def _decorate(fn):
        def _wrapper(*args):
            cursor = db.cursor()
            isolate, db.isolation_level = db.isolation_level, None
            try:
                result = fn(cursor, *args)
                db.commit()
                return result
            except sqlite3.IntegrityError:
                db.rollback()
                raise
            finally:
                isolate, db.isolation_level = db.isolation_level, isolate  # restore to the initial setting
        return _wrapper
    return _decorate


def verify_sd_blob(sd_hash, blob_dir):
    with open(os.path.join(blob_dir, sd_hash), "r") as sd_file:
        data = sd_file.read()
        sd_length = len(data)
        decoded = json.loads(data)
    assert set(decoded.keys()) == {
        'stream_name', 'blobs', 'stream_type', 'key', 'suggested_file_name', 'stream_hash'
    }, "invalid sd blob"
    for i, blob in enumerate(sorted(decoded['blobs'], key=lambda x: int(x['blob_num']), reverse=True)):
        if blob['blob_num'] == len(decoded['blobs']) - 1:
            assert 'blob_hash' not in blob, 'stream terminator should not have a blob hash'
            assert blob['length'] == 0, 'non zero length stream terminator'
        else:
            assert 'blob_hash' in blob and blob['length'] > 0, 'invalid stream blob'
    return decoded, sd_length


def do_migration(db_dir):
    new_db_path = os.path.join(db_dir, "lbrynet.sqlite")
    connection = sqlite3.connect(new_db_path)

    metadata_db = sqlite3.connect(os.path.join(db_dir, "blockchainname.db"))
    lbryfile_db = sqlite3.connect(os.path.join(db_dir, 'lbryfile_info.db'))
    blobs_db = sqlite3.connect(os.path.join(db_dir, 'blobs.db'))

    name_metadata_cursor = metadata_db.cursor()
    lbryfile_cursor = lbryfile_db.cursor()
    blobs_db_cursor = blobs_db.cursor()

    old_outpoint_to_rowid = {
        rowid: (txid, nout) for (rowid, txid, nout) in
        lbryfile_cursor.execute("select * from lbry_file_metadata").fetchall()
    }

    old_outpoint_to_sd_hash = {
        sd_hash: (txid, nout) for (_, txid, nout, sd_hash) in
        name_metadata_cursor.execute("select * from name_metadata").fetchall()
    }

    sd_outpoints = set(old_outpoint_to_sd_hash.values())
    rowid_outpoints = set(old_outpoint_to_rowid.values())

    claims = {
        outpoint: name_metadata_cursor.execute(
            "select c.claimId, c.name, claim_cache.claim_sequence, claim_cache.claim_address, "
            "claim_cache.height, claim_cache.amount, claim_cache.claim_pb "
            "from claim_cache inner join claim_ids c on claim_cache.claim_id=c.claimId "
            "where c.txid=? and c.n=?", outpoint
        ).fetchone()
        for outpoint in sd_outpoints.union(rowid_outpoints)
    }

    @run_operation(connection)
    def _populate_blobs(transaction, blob_infos):
        for (blob_hash, blob_length, _, next_announce_time, should_announce) in blob_infos:
            transaction.execute(
                "INSERT INTO blob VALUES (?, ?, ?, ?, ?)",
                (blob_hash, blob_length, int(next_announce_time), should_announce, "finished")
            )

    @run_operation(connection)
    def _import_file(transaction, rowid, sd_hash, stream_hash, key, stream_name, suggested_file_name, data_rate,
                     status, stream_blobs):
        # insert the stream
        transaction.execute(
            "INSERT OR IGNORE INTO stream VALUES (?, ?, ?, ?, ?)",
            (stream_hash, sd_hash, key, stream_name, suggested_file_name)
        )

        # insert the stream blobs
        for (blob_hash, position, iv) in stream_blobs:
            transaction.execute(
                "INSERT OR IGNORE INTO stream_blob VALUES (?, ?, ?, ?)",
                (stream_hash, blob_hash, position, iv)
            )

        # insert the file
        transaction.execute(
            "INSERT OR IGNORE INTO file VALUES (?, ?, ?, ?, ?)",
            (stream_hash, stream_name, default_download_directory.encode('hex'),
             data_rate, status)
        )

        # try to link the file to a content claim
        if rowid in old_outpoint_to_rowid:
            outpoint = old_outpoint_to_rowid[rowid]
        elif sd_hash in old_outpoint_to_sd_hash:
            outpoint = old_outpoint_to_sd_hash[sd_hash]
        else:
            outpoint = None
        if outpoint and outpoint in claims:
            claim_id, name, sequence, address, height, amount, serialized = claims[outpoint]
            transaction.execute(
                "INSERT OR IGNORE INTO claim VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("%s:%i" % outpoint, claim_id, name, amount, height, serialized,
                 smart_decode(serialized).certificate_id, address, sequence)
            )
            transaction.execute(
                "INSERT OR IGNORE INTO content_claim VALUES (?, ?)", (stream_hash, "%s:%i" % outpoint)
            )

    @run_operation(connection)
    def _add_recovered_blobs(transaction, blob_infos, sd_hash, sd_length):
        transaction.execute(
            "insert or replace into blob values (?, ?, ?, ?, ?)", (sd_hash, sd_length, 0, 1, "finished")
        )
        for i, blob_info in enumerate(
                sorted(blob_infos, key=lambda x: x['blob_num'], reverse=True)):
            if blob_info['blob_num'] < len(blob_infos) - 1:
                transaction.execute(
                    "insert or ignore into blob values (?, ?, ?, ?, ?)",
                    (blob_info['blob_hash'], blob_info['length'], 0, 0 if i else 1, "pending")
                )

    @run_operation(connection)
    def _make_db(new_db):
        # create the new tables
        new_db.executescript(SQLiteStorage.CREATE_TABLES_QUERY)

        # first migrate the blobs
        blobs = blobs_db_cursor.execute("SELECT * FROM blobs").fetchall()
        _populate_blobs(blobs)
        damaged_stream_sds = []
        imported_stream_sds = []

        # used to store the query arguments if we need to try re-importing the lbry file later
        rerun_args = {}  # <sd_hash>: args tuple

        # migrate the lbry files
        for (rowid, sd_hash, stream_hash, key, stream_name,
             suggested_file_name, data_rate, status) in lbryfile_cursor.execute(
                "SELECT lbry_files.ROWID, d.sd_blob_hash, lbry_files.*, o.blob_data_rate, o.status FROM lbry_files "
                "INNER JOIN lbry_file_descriptors d ON lbry_files.stream_hash=d.stream_hash "
                "INNER JOIN lbry_file_options o ON lbry_files.stream_hash=o.stream_hash").fetchall():
            stream_blobs = []
            try:
                stream_blobs = lbryfile_cursor.execute(
                    "SELECT blob_hash, position, iv FROM lbry_file_blobs "
                    "INNER JOIN lbry_files l ON lbry_file_blobs.stream_hash=l.stream_hash "
                    "WHERE l.stream_hash=? "
                    "ORDER BY position ASC", (stream_hash,)
                ).fetchall()
                _import_file(
                    rowid, sd_hash, stream_hash, key, stream_name, suggested_file_name, data_rate or 0.0, status,
                    stream_blobs
                )
                imported_stream_sds.append(sd_hash)
            except sqlite3.IntegrityError:
                # stash the query arguments to try again if the sd blob can be read
                rerun_args[sd_hash] = (rowid, sd_hash, stream_hash, key, stream_name, suggested_file_name,
                                       data_rate or 0.0, status, stream_blobs)
                damaged_stream_sds.append(sd_hash)

        if damaged_stream_sds:
            blob_dir = os.path.join(db_dir, "blobfiles")
            damaged_sds_on_disk = [] if not os.path.isdir(blob_dir) else list({p for p in os.listdir(blob_dir)
                                                                               if p in damaged_stream_sds})
            for damaged_sd in damaged_sds_on_disk:
                try:
                    decoded, sd_length = verify_sd_blob(damaged_sd, blob_dir)
                    _add_recovered_blobs(decoded['blobs'], damaged_sd, sd_length)
                    _import_file(*rerun_args[damaged_sd])
                    damaged_stream_sds.remove(damaged_sd)
                    imported_stream_sds.append(damaged_sd)
                except (OSError, ValueError, TypeError, IOError, AssertionError, sqlite3.IntegrityError) as err:
                    continue

        log.info("imported %i lbry files, failed to import %i", len(imported_stream_sds), len(damaged_stream_sds))

    _make_db()
    connection.close()
    blobs_db.close()
    lbryfile_db.close()
    metadata_db.close()
    os.remove(os.path.join(db_dir, "blockchainname.db"))
    os.remove(os.path.join(db_dir, "lbryfile_info.db"))
    os.remove(os.path.join(db_dir, "blobs.db"))
