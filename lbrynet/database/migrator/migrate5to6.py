import sqlite3
import os
import logging
from lbrynet.database.storage import SQLiteStorage

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


def do_migration(db_dir):
    log.info("Doing the migration")
    db_refactor(db_dir)
    log.info("Migration succeeded")


def db_refactor(db_dir):
    new_db_path = os.path.join(db_dir, "lbrynet.sqlite")

    name_metadata_path = os.path.join(db_dir, "blockchainname.db")
    lbryfile_info_db_path = os.path.join(db_dir, 'lbryfile_info.db')
    blobs_db_path = os.path.join(db_dir, 'blobs.db')

    name_metadata_db = sqlite3.connect(name_metadata_path)
    lbryfile_db = sqlite3.connect(lbryfile_info_db_path)
    new_db = sqlite3.connect(new_db_path)
    blobs_db = sqlite3.connect(blobs_db_path)

    name_metadata_cursor = name_metadata_db.cursor()
    lbryfile_cursor = lbryfile_db.cursor()
    new_db_cursor = new_db.cursor()
    blobs_db_cursor = blobs_db.cursor()

    new_db.executescript(SQLiteStorage.CREATE_TABLES_QUERY)
    new_db.commit()

    stream_descriptors = lbryfile_cursor.execute("select * from lbry_file_descriptors").fetchall()
    file_infos = {x[1]: {'sd_hash': x[0]} for x in stream_descriptors}
    file_options = lbryfile_cursor.execute(
            "select blob_data_rate, status, stream_hash from lbry_file_options"
    ).fetchall()
    for (rate, status, stream_hash) in file_options:
        file_infos[stream_hash]['status'] = status
        file_infos[stream_hash]['rate'] = rate
    streams = lbryfile_cursor.execute("select rowid, * from lbry_files").fetchall()
    for s in streams:
        file_infos[s[1]]['rowid'] = s[0]
        file_infos[s[1]]['file_name'] = s[4]
    stream_blobs = lbryfile_cursor.execute(
        "select stream_hash, blob_hash, position, iv from lbry_file_blobs"
    ).fetchall()

    for stream_hash in file_infos.keys():
        txid, nout = lbryfile_cursor.execute(
            "select txid, n from lbry_file_metadata where lbry_file=?",
            (file_infos[stream_hash]['rowid'],)
        ).fetchone()
        if txid is None or nout is None:
            log.warning("Missing outpoint, cannot migrate stream %s", stream_hash)
            del file_infos[stream_hash]
            continue
        claim_info = name_metadata_cursor.execute(
            "select claimId, name from claim_ids where txid=? and n=?", (txid, nout)
        ).fetchone()
        if not claim_info:
            log.warning("Missing claim id, cannot migrate stream %s", stream_hash)
            del file_infos[stream_hash]
            continue
        claim_id, name = claim_info
        file_infos[stream_hash]['claim_name'] = name
        file_infos[stream_hash]['claim_id'] = claim_id
        file_infos[stream_hash]['outpoint'] = "%s:%i" % (txid, nout)

    blobs = blobs_db_cursor.execute("select * from blobs").fetchall()

    for (blob_hash, blob_length, _, next_announce_time, should_announce) in blobs:
        new_db.execute(
            "insert into blob values (?, ?, ?, ?)", (blob_hash, blob_length,
                                                     int(next_announce_time), should_announce)
        )
    new_db.commit()

    for s in streams:
        if s[1] in file_infos:
            new_db_cursor.execute(
                "insert into stream values (?, ?, ?, ?, ?)",
                (s[1], file_infos[s[1]]['sd_hash'], s[2], s[3], s[4])
            )
    new_db.commit()

    for (stream_hash, blob_hash, position, iv) in stream_blobs:
        if stream_hash in file_infos:
            new_db_cursor.execute(
                "insert into stream_blob values (?, ?, ?, ?)", (stream_hash, blob_hash,
                                                                position, iv)
            )

    for stream_hash, file_info in file_infos.iteritems():
        new_db_cursor.execute(
            "insert into claim values (?, ?, ?, ?, ?)",
            (file_info['outpoint'], file_info['claim_id'], file_info['claim_name'], 0, None)
        )
        new_db.commit()
        new_db_cursor.execute(
            "insert into file values (?, ?, ?, ?, ?)",
            (stream_hash, file_info['outpoint'], file_info['file_name'], file_info['rate'],
             file_info['status'])
        )
        new_db.commit()

    new_db.commit()
    new_db.close()
    blobs_db.close()
    lbryfile_db.close()
    name_metadata_db.close()

    os.remove(lbryfile_info_db_path)
    os.remove(name_metadata_path)
