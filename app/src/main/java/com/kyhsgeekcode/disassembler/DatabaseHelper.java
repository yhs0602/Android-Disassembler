package com.kyhsgeekcode.disassembler;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;
import java.util.List;

//import info.androidhive.sqlite.database.model.Note;
//https://www-androidhive-info.cdn.ampproject.org/v/s/www.androidhive.info/2011/11/android-sqlite-database-tutorial/amp/?amp_js_v=0.1&usqp=mq331AQICAEoAWAAaAA%3D#top
public class DatabaseHelper extends SQLiteOpenHelper {

    // Database Version
    private static final int DATABASE_VERSION = 1;

    // Database Name - let custom path do
    // private static final String DATABASE_NAME = "notes_db";

    public DatabaseHelper(Context context, String path) {
        super(context, path, null, DATABASE_VERSION);
    }

    // Creating Tables
    @Override
    public void onCreate(SQLiteDatabase db) {
        // create notes table
        db.execSQL(DisasmResult.CREATE_TABLE);
    }

    // Upgrading database
    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // Drop older table if existed
        db.execSQL("DROP TABLE IF EXISTS " + DisasmResult.TABLE_NAME);

        // Create tables again
        onCreate(db);
    }

    public long insert(DisasmResult dar) {
        // get writable database as we want to write data
        SQLiteDatabase db = this.getWritableDatabase();

        ContentValues values = new ContentValues();
        // ???`id` and `timestamp` will be inserted automatically.

        values.put(DisasmResult.COLUMN_ADDRESS, dar.getAddress());
        values.put(DisasmResult.COLUMN_BYTES, dar.getBytes());
        values.put(DisasmResult.COLUMN_GROUP, dar.getGroups());
        values.put(DisasmResult.COLUMN_GROUP_CNT, dar.getGroups_count());
        values.put(DisasmResult.COLUMN_ID, dar.getId());
        values.put(DisasmResult.COLUMN_MNEMONIC, dar.getMnemonic());
        values.put(DisasmResult.COLUMN_OPSTR, dar.getOp_str());
        values.put(DisasmResult.COLUMN_REGREAD, dar.getRegs_read());
        values.put(DisasmResult.COLUMN_REGREAD_CNT, dar.getRegs_read_count());
        values.put(DisasmResult.COLUMN_REGWRITE, dar.getRegs_write());
        values.put(DisasmResult.COLUMN_REGWRITE_CNT, dar.getRegs_write_count());
        values.put(DisasmResult.COLUMN_SIZE, dar.getSize());

        // insert row
        long id = db.insert(DisasmResult.TABLE_NAME, null, values);

        // close db connection
        db.close();

        // return newly inserted row id
        return id;
    }

    /*
        public DisasmResult getNote(long id) {
            // get readable database as we are not inserting anything
            SQLiteDatabase db = this.getReadableDatabase();

            Cursor cursor = db.query(DisasmResult.TABLE_NAME,
                                     new String[]{DisasmResult.COLUMN_ID, DisasmResultDBUnit.COLUMN_NOTE, DisasmResultDBUnit.COLUMN_TIMESTAMP},
                                     DisasmResult.COLUMN_ID + "=?",
                                     new String[]{String.valueOf(id)}, null, null, null, null);

            if (cursor != null)
                cursor.moveToFirst();

            // prepare note object
            DisasmResult note = new DisasmResult(
                cursor.getInt(cursor.getColumnIndex(DisasmResult.COLUMN_ID)),
                cursor.getString(cursor.getColumnIndex(DisasmResult.COLUMN_ADDRESS)),
                cursor.getString(cursor.getColumnIndex(DisasmResult.COLUMN_BYTES)));

            // close the db connection
            cursor.close();

            return note;
        }
    */
    public List<DisasmResult> getAll() {
        List<DisasmResult> dars = new ArrayList<>();

        // Select All Query
        String selectQuery = "SELECT  * FROM " + DisasmResult.TABLE_NAME + " ORDER BY " +
                DisasmResult.COLUMN_BYTES + " DESC";

        SQLiteDatabase db = this.getWritableDatabase();
        Cursor cursor = db.rawQuery(selectQuery, null);

        // looping through all rows and adding to list
        if (cursor.moveToFirst()) {

            do {
                DisasmResult dar = new DisasmResult();
                dar.setId(cursor.getInt(cursor.getColumnIndex(DisasmResult.COLUMN_ID)));
                //Should it be getLong()?
                dar.setAddress(cursor.getInt(cursor.getColumnIndex(DisasmResult.COLUMN_ADDRESS)));
                dar.setBytes(cursor.getBlob(cursor.getColumnIndex(DisasmResult.COLUMN_BYTES)));
                dar.setGroups(cursor.getBlob(cursor.getColumnIndex(DisasmResult.COLUMN_GROUP)));
                dar.setGroups_count((byte) cursor.getInt(cursor.getColumnIndex(DisasmResult.COLUMN_GROUP_CNT)));
                dar.setRegs_read(cursor.getBlob(cursor.getColumnIndex(DisasmResult.COLUMN_REGREAD)));
                dar.setRegs_read_count((byte) cursor.getInt(cursor.getColumnIndex(DisasmResult.COLUMN_REGREAD_CNT)));
                dar.setRegs_write(cursor.getBlob(cursor.getColumnIndex(DisasmResult.COLUMN_REGWRITE)));
                dar.setRegs_write_count((byte) cursor.getInt(cursor.getColumnIndex(DisasmResult.COLUMN_REGWRITE_CNT)));
                dar.setMnemonic(cursor.getString(cursor.getColumnIndex(DisasmResult.COLUMN_MNEMONIC)));
                dar.setOp_str(cursor.getString(cursor.getColumnIndex(DisasmResult.COLUMN_OPSTR)));
                dar.setSize(cursor.getInt(cursor.getColumnIndex(DisasmResult.COLUMN_SIZE)));
                dars.add(dar);
            } while (cursor.moveToNext());
        }

        // close db connection
        db.close();

        // return notes list
        return dars;
    }

    public int getCount() {
        String countQuery = "SELECT  * FROM " + DisasmResult.TABLE_NAME;
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.rawQuery(countQuery, null);

        int count = cursor.getCount();
        cursor.close();


        // return count
        return count;
    }

    /*
        public int updateNote(DisasmResult note) {
            SQLiteDatabase db = this.getWritableDatabase();

            ContentValues values = new ContentValues();
            values.put(DisasmResult.COLUMN_ADDRESS, note.getNote());

            // updating row
            return db.update(DisasmResult.TABLE_NAME, values, DisasmResult.COLUMN_ID + " = ?",
                             new String[]{String.valueOf(note.getId())});
        }
    */
    public void deleteNote(DisasmResult note) {
        SQLiteDatabase db = this.getWritableDatabase();
        db.delete(DisasmResult.TABLE_NAME, DisasmResult.COLUMN_ADDRESS + " = ?",
                new String[]{String.valueOf(note.getAddress())});
        db.close();
    }
//	public static final String CREATE_TABLE =
//	"CREATE TABLE " + TABLE_NAME + "("
//	+ COLUMN_ID + " INTEGER, "
//	+ COLUMN_ADDRESS + " INTEGER PRIMARY KEY, "
//	+ COLUMN_SIZE + " INTEGER, "
//	+ COLUMN_BYTES + " CHAR(16), "
//	+ COLUMN_MNEMONIC + " TEXT, "
//	+ COLUMN_OPSTR + " TEXT, "
//	+ COLUMN_REGREAD + " CHAR(12), "
//	+ COLUMN_REGREAD_CNT + " INTEGER, "
//	+ COLUMN_REGWRITE + " CHAR(12), "
//	+ COLUMN_REGWRITE_CNT + " INTEGER, "
//	+ COLUMN_GROUP + " CHAR(8), "
//	+ COLUMN_GROUP_CNT + " INTEGER "
//	+ ")";

}
