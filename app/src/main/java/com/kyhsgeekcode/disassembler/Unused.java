package com.kyhsgeekcode.disassembler;

public class Unused {


	/*	OnCreate()
	 vp = (ViewPager)findViewById(R.id.pager);
	 Button btn_first = (Button)findViewById(R.id.btn_first);
	 Button btn_second = (Button)findViewById(R.id.btn_second);
	 Button btn_third = (Button)findViewById(R.id.btn_third);

	 vp.setAdapter(new pagerAdapter(getSupportFragmentManager()));
	 vp.setCurrentItem(0);

	 btn_first.setOnClickListener(movePageListener);
	 btn_first.setTag(0);
	 btn_second.setOnClickListener(movePageListener);
	 btn_second.setTag(1);
	 btn_third.setOnClickListener(movePageListener);
	 btn_third.setTag(2);*/
// Adapter 생성
// adapter = new DisasmListViewAdapter() ;
	/*	ListViewItem item=new ListViewItem();
	 item.setAddress("address");
	 item.setBytes("bytes");
	 item.setComments("comments");
	 item.setCondition("condition");
	 item.setInstruction("inst");
	 item.setLabel("label");
	 item.setOperands("operands");
	 adapter.addItem(item);
	 // 리스트뷰 참조 및 Adapter달기
	 listview = (ListView) findViewById(R.id.lvDisassembly);
	 listview.setAdapter(adapter);
	 listview.setOnTouchListener(new ListView.OnTouchListener() {
	 @Override
	 public boolean onTouch(View v, MotionEvent event) {
	 int action = event.getAction();
	 switch (action) {
	 case MotionEvent.ACTION_DOWN:
	 // Disallow ScrollView to intercept touch events.
	 v.getParent().requestDisallowInterceptTouchEvent(true);
	 break;

	 case MotionEvent.ACTION_UP:
	 // Allow ScrollView to intercept touch events.
	 v.getParent().requestDisallowInterceptTouchEvent(false);
	 break;
	 }

	 // Handle ListView touch events.
	 v.onTouchEvent(event);
	 return true;
	 }});
	 // 위에서 생성한 listview에 클릭 이벤트 핸들러 정의.
	 listview.setOnItemClickListener(new AdapterView.OnItemClickListener() {
	 @Override
	 public void onItemClick(AdapterView parent, View v, int position, long id) {
	 // get item
	 ListViewItem item = (ListViewItem) parent.getItemAtPosition(position) ;

	 //String titleStr = item.getTitle() ;
	 //String descStr = item.getDesc() ;
	 //Drawable iconDrawable = item.getIcon() ;

	 // TODO : use item data.
	 }
	 }) ;*/
	/*
	 PrintStackTrace to string
	 ByteArrayOutputStream out = new ByteArrayOutputStream();
	 PrintStream pinrtStream = new PrintStream(out);
	 e.printStackTrace(pinrtStream);
	 String stackTraceString = out.toString(); // 찍은 값을 가져오고.

	 */
	/*
	 public void onWindowFocusChanged(boolean hasFocus) {
	 // get content height
	 int contentHeight = listview.getChildAt(0).getHeight();
	 contentHeight*=listview.getChildCount();
	 // set listview height
	 LayoutParams lp = listview.getLayoutParams();
	 lp.height = contentHeight;
	 listview.setLayoutParams(lp);
	 }
	 */

	/*    switch(id) {
	 case R.id.menu_login:
	 Toast.makeText(getApplicationContext(), "로그인 메뉴 클릭",
	 Toast.LENGTH_SHORT).show();
	 return true;
	 case R.id.menu_logout:
	 Toast.makeText(getApplicationContext(), "로그아웃 메뉴 클릭",
	 Toast.LENGTH_SHORT).show();
	 return true;
	 case R.id.menu_a:
	 Toast.makeText(getApplicationContext(), "다음",
	 Toast.LENGTH_SHORT).show();
	 return true;
	 }*/
	/*
	 View.OnClickListener movePageListener = new View.OnClickListener()
	 {
	 @Override
	 public void onClick(View v)
	 {
	 int tag = (int) v.getTag();
	 vp.setCurrentItem(tag);
	 }
	 };

	 private class pagerAdapter extends FragmentStatePagerAdapter
	 {
	 public pagerAdapter(android.support.v4.app.FragmentManager fm)
	 {
	 super(fm);
	 }
	 @Override
	 public android.support.v4.app.Fragment getItem(int position)
	 {
	 switch(position)
	 {
	 case 0:
	 return new OverviewFragment();
	 case 1:
	 return new OverviewFragment();
	 case 2:
	 return new OverviewFragment();
	 default:
	 return null;
	 }
	 }
	 @Override
	 public int getCount()
	 {
	 return 3;
	 }
	 }*/
//details.setText("file format not recognized.");
//	String result=sample.getText().toString();
//Toast toast = Toast.makeText(myActivity, result, Toast.LENGTH_LONG);
//toast.show();
	/*PE pe=PEParser.parse(fpath);
	 if (pe != null)
	 {
	 PESignature ps =pe.getSignature();
	 if (ps == null || !ps.isValid())
	 {
	 //What is it?
	 Toast.makeText(this, "The file seems that it is neither a valid Elf file or PE file!", Toast.LENGTH_SHORT).show();
	 throw new IOException(e);
	 }
	 }
	 else
	 {
	 //What is it?
	 Toast.makeText(this, "The file seems that it is neither a valid Elf file or PE file!", Toast.LENGTH_SHORT).show();
	 throw new IOException(e);
	 }*/
/*
	 private void CreateDisasmTopRow(TableRow tbrow0)
	 {
	 TextView tv0 = new TextView(MainActivity.this);
	 tv0.setText(" Address ");
	 tv0.setTextColor(Color.BLACK);
	 tbrow0.addView(tv0);
	 TextView tv1 = new TextView(MainActivity.this);
	 tv1.setText(" Label ");
	 tv1.setTextColor(Color.BLACK);
	 tbrow0.addView(tv1);
	 TextView tv2 = new TextView(MainActivity.this);
	 tv2.setText(" Bytes ");
	 tv2.setTextColor(Color.BLACK);
	 tbrow0.addView(tv2);
	 TextView tv3 = new TextView(MainActivity.this);
	 tv3.setText(" Inst ");
	 tv3.setTextColor(Color.BLACK);
	 tbrow0.addView(tv3);
	 TextView tv4 = new TextView(MainActivity.this);
	 tv4.setText(" Cond ");
	 tv4.setTextColor(Color.BLACK);
	 tbrow0.addView(tv4);
	 TextView tv5 = new TextView(MainActivity.this);
	 tv5.setText(" Operands ");
	 tv5.setTextColor(Color.BLACK);
	 tbrow0.addView(tv5);
	 TextView tv6 = new TextView(MainActivity.this);
	 tv6.setText(" Comment ");
	 tv6.setTextColor(Color.BLACK);
	 AdjustShow(tv0, tv1, tv2, tv3, tv4, tv5, tv6);
	 tbrow0.addView(tv6);
	 }
	 */
	 /*
				 private String[] getAccounts() {
				 Pattern emailPattern = Patterns.EMAIL_ADDRESS;
				 Account[] accounts = AccountManager.get(MainActivity.this).getAccounts();
				 if(accounts==null)
				 {
				 return new String[]{""};
				 }
				 ArrayList<String> accs=new ArrayList<>();
				 for (Account account : accounts) {
				 if (emailPattern.matcher(account.name).matches()) {
				 String email = account.name;
				 accs.add(email);
				 //Log.d(TAG, "email : " + email);
				 }
				 }
				 return accs.toArray(new String[accs.size()]);
				 }*/
/**
 * Swaps fragments in the main content view
 * <p>
 * private void selectItem(int position) {
 * //Project project=
 * // Create a new fragment and specify the planet to show based on position
 * /*Fragment fragment = new PlanetFragment();
 * Bundle args = new Bundle();
 * args.putInt(PlanetFragment.ARG_PLANET_NUMBER, position);
 * fragment.setArguments(args);
 * <p>
 * // Insert the fragment by replacing any existing fragment
 * FragmentManager fragmentManager = getFragmentManager();
 * fragmentManager.beginTransaction()
 * .replace(R.id.content_frame, fragment)
 * .commit();
 * <p>
 * // Highlight the selected item, update the title, and close the drawer
 * mDrawerList.setItemChecked(position, true);
 * setTitle(mPlanetTitles[position]);
 * mDrawerLayout.closeDrawer(mDrawerList);
 * }
 */

/*
    class SaveDBAsync extends AsyncTask<DatabaseHelper, Integer, Void> {
        String TAG = getClass().getSimpleName();
        android.app.AlertDialog.Builder builder;
        ProgressBar progress;

        protected void onPreExecute() {
            super.onPreExecute();
            Log.d(TAG + " PreExceute", "On pre Exceute......");
            progress = new ProgressBar(MainActivity.this);
            progress.setIndeterminate(false);

            builder = new android.app.AlertDialog.Builder(MainActivity.this);
            builder.setTitle("Saving..").setView(progress);
            builder.show();
        }

        protected Void doInBackground(DatabaseHelper... disasmF) {
            Log.d(TAG + " DoINBackGround", "On doInBackground...");

            int cnt = disasmF[0].getCount();
            if (cnt == 0) {
                int datasize = disasmResults.size();
                for (int i = 0; i < datasize; ++i) {
                    //disasmF[0].insert(disasmResults.get(i));
                    publishProgress(i);
                }
            }
            return null;
        }

        protected void onProgressUpdate(Integer... a) {
            super.onProgressUpdate(a);
            progress.setProgress(a[0]);
            //Log.d(TAG + " onProgressUpdate", "You are in progress update ... " + a[0]);
        }

    }

    class SaveDisasmAsync extends AsyncTask<Void, Integer, Void> {
        //String TAG = getClass().getSimpleName();
        android.app.AlertDialog.Builder builder;
        ProgressBar progress;

        protected void onPreExecute() {
            super.onPreExecute();
            Log.d(TAG + " PreExceute", "On pre Exceute......");
            progress = new ProgressBar(MainActivity.this);
            progress.setIndeterminate(false);

            builder = new android.app.AlertDialog.Builder(MainActivity.this);
            builder.setTitle("Saving..").setView(progress);
            builder.show();
        }

        protected Void doInBackground(Void... list) {
            Log.d(TAG + " DoINBkGnd", "On doInBackground...");
            SaveDisasmRaw();
            return null;
        }

        protected void onProgressUpdate(Integer... a) {
            super.onProgressUpdate(a);
            progress.setProgress(a[0]);
            //Log.d(TAG + " onProgressUpdate", "You are in progress update ... " + a[0]);
        }

		/*
		 protected void onPostExecute(Void result) {
		 super.onPostExecute(result);
		 //Log.d(TAG + " onPostExecute", "" + result);
		 }
		 * /
    }
*/
/*    //FIXME, TODO

   /////////////////////////////////////////////Export - Output//////////////////////////////////
    public void ExportDisasm() {
        ExportDisasm(null);
    }

    private void ExportDisasm(final Runnable runnable) {
        requestAppPermissions(this);
        if (fpath == null || "".compareToIgnoreCase(fpath) == 0) {
            AlertSelFile();
            return;
        }
        Toast.makeText(this, "Sorry, not stable yet", Toast.LENGTH_SHORT).show();
        if (true)
            return;
        if (currentProject == null) {
            final EditText etName = new EditText(this);
            ShowEditDialog(getString(R.string.newProject), getString(R.string.enterNewProjName), etName, getString(R.string.ok), new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface p1, int p2) {

                    String projn = etName.getText().toString();
                    SaveDisasmNewProject(projn, runnable);
                }
            }, getString(R.string.cancel), new DialogInterface.OnClickListener() {

                @Override
                public void onClick(DialogInterface p1, int p2) {
                }
            });
        } else {
            ShowExportOptions(runnable);
        }

    }

    ////////////////////////////////////////////End Export - Output/////////////////////////////////////////


    private void ExportDisasmSub(int mode) {
        Log.v(TAG, "Saving disassembly");
        if (mode == 0)//Raw mode
        {
            SaveDisasmRaw();
            return;
        }
        if (mode == 4)//Database mode
        {
            //SaveDisasm(currentProject.getDisasmDb());
            return;
        }
        File dir = new File(ProjectManager.RootFile, currentProject.name + "/");
        Log.d(TAG, "dirpath=" + dir.getAbsolutePath());
        File file = new File(dir, "Disassembly_" + new Date(System.currentTimeMillis()).toString() + (mode == 3 ? ".json" : ".txt"));
        Log.d(TAG, "filepath=" + file.getAbsolutePath());
        dir.mkdirs();
        try {
            file.createNewFile();
        } catch (IOException e) {
            Log.e(TAG, "", e);
            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show();
        }
        //Editable et=etDetails.getText();
        try {
            FileOutputStream fos = new FileOutputStream(file);
            try {
                StringBuilder sb = new StringBuilder();
                ArrayList<ListViewItem>/*ListViewItem[]* / items = new ArrayList<>();
                //items.addAll(adapter.itemList());
                for (ListViewItem lvi : items) {
                    switch (mode) {
                        case 1:
                            sb.append(lvi.address);
                            sb.append("\t");
                            sb.append(lvi.bytes);
                            sb.append("\t");
                            sb.append(lvi.instruction);
                            sb.append(" ");
                            sb.append(lvi.operands);
                            sb.append("\t");
                            sb.append(lvi.comments);
                            break;
                        case 2:
                            sb.append(lvi.address);
                            sb.append(":");
                            sb.append(lvi.instruction);
                            sb.append(" ");
                            sb.append(lvi.operands);
                            sb.append("  ;");
                            sb.append(lvi.comments);
                            break;
                        case 3:
                            sb.append(lvi.toString());
                    }
                    sb.append(System.lineSeparator());
                }
                fos.write(sb.toString().getBytes());
            } catch (IOException e) {
                AlertError("", e);
                return;
            }
        } catch (FileNotFoundException e) {
            AlertError("", e);
        }
        AlertSaveSuccess(file);
    }

    private void SaveDisasmRaw() {
        File dir = new File(ProjectManager.RootFile, currentProject.name + "/");
        Log.d(TAG, "dirpath=" + dir.getAbsolutePath());
        File file = new File(dir, "Disassembly.raw");
        Log.d(TAG, "filepath=" + file.getAbsolutePath());
        dir.mkdirs();
        try {
            file.createNewFile();
        } catch (IOException e) {
            Log.e(TAG, "", e);
            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show();
        }
        try {
            FileOutputStream fos = new FileOutputStream(file);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(disasmResults);
            oos.close();
        } catch (IOException e) {
            AlertError(getString(R.string.failSaveFile), e);
            return;
        }
        AlertSaveSuccess(file);
    }

    private void SaveDetail() {
        SaveDetail(null);
    }

    private void SaveDetail(final Runnable runnable) {
        requestAppPermissions(this);
        if (fpath == null || "".compareToIgnoreCase(fpath) == 0) {
            AlertSelFile();
            return;
        }
        if (currentProject == null) {
            final EditText etName = new EditText(this);
            ShowEditDialog(getString(R.string.newProject), getString(R.string.enterNewProjName), etName, getString(R.string.ok), new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface p1, int p2) {

                    String projn = etName.getText().toString();
                    SaveDetailNewProject(projn);
                    if (runnable != null)
                        runnable.run();
                }
            }, getString(R.string.cancel), new DialogInterface.OnClickListener() {

                @Override
                public void onClick(DialogInterface p1, int p2) {

                }
            });
        } else {
            try {
                SaveDetailSub(currentProject);
                if (runnable != null)
                    runnable.run();
            } catch (IOException e) {
                AlertError(getString(R.string.failSaveFile), e);
            }
        }

        //SaveDetailOld();
    }

    private void SaveDetail(File dir, File file) {
        dir.mkdirs();
        try {
            file.createNewFile();
        } catch (IOException e) {
            Log.e(TAG, "", e);
            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show();
        }

        try {
            FileOutputStream fos = new FileOutputStream(file);
            try {
                fos.write(parsedFile.toString().getBytes());
            } catch (IOException e) {
                Log.e(TAG, "", e);
            }
        } catch (FileNotFoundException e) {
            Log.e(TAG, "", e);
        }

        AlertSaveSuccess(file);
    }

    private void SaveDetailNewProject(String projn) {

        try {
            ProjectManager.Project proj = projectManager.newProject(projn, fpath);
            proj.Open(false);
            db = new DatabaseHelper(this, ProjectManager.createPath(proj.name) + "disasm.db");
            SaveDetailSub(proj);
        } catch (IOException e) {
            AlertError(R.string.failCreateProject, e);
        }
    }

    private void SaveDetailSub(ProjectManager.Project proj) throws IOException {
        File detailF = proj.getDetailFile();
        if (detailF == null)
            throw new IOException("Failed to create detail File");
        currentProject = proj;
        detailF.createNewFile();
        SaveDetail(new File(ProjectManager.Path), detailF);
        proj.Save();
    }

    private void SaveDisasmNewProject(String projn) {
        SaveDisasmNewProject(projn, null);
    }

    private void SaveDisasmNewProject(String projn, Runnable runnable) {
        try {
            ProjectManager.Project proj = projectManager.newProject(projn, fpath);
            currentProject = proj;
            proj.Open(false);
            db = new DatabaseHelper(this, ProjectManager.createPath(proj.name) + "disasm.db");
            ShowExportOptions(runnable);
            proj.Save();

        } catch (IOException e) {
            AlertError(getString(R.string.failCreateProject), e);
        }
    }

    private void ShowExportOptions() {
        ShowExportOptions(null);
    }

    private void ShowExportOptions(final Runnable runnable) {
        final List<String> ListItems = new ArrayList<>();
        ListItems.add("Raw(Fast,Reloadable)");
        ListItems.add("Classic(Addr bytes inst op comment)");
        ListItems.add("Simple(Addr: inst op; comment");
        ListItems.add("Json");
        ListItems.add("Database(.db, reloadable)");
        ShowSelDialog(this, ListItems, getString(R.string.export_as), new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int pos) {
                //String selectedText = items[pos].toString();
                dialog.dismiss();
                final ProgressDialog dialog2 = showProgressDialog(getString(R.string.saving));
                ExportDisasmSub(pos);
                if (runnable != null)
                    runnable.run();
                dialog2.dismiss();
            }
        });
    }

    private void createZip() {
        File targetFile;
        try {
            File projFolder = new File(ProjectManager.RootFile, currentProject.name + "/");
            FileOutputStream fos = new FileOutputStream(targetFile = new File(ProjectManager.RootFile, currentProject.name + ".zip"));
            ZipOutputStream zos = new ZipOutputStream(fos);
            File[] targets = projFolder.listFiles();
            byte[] buf = new byte[4096];
            int readlen;
            for (File file : targets) {
                Log.v(TAG, "writing " + file.getName());
                ZipEntry ze = new ZipEntry(file.getName());
                zos.putNextEntry(ze);
                FileInputStream fis = new FileInputStream(file);
                while ((readlen = fis.read(buf, 0, 4096)) > 0)
                    zos.write(buf, 0, readlen);
                zos.closeEntry();
                fis.close();
            }
            zos.close();
            fos.close();
        } catch (Exception e) {
            AlertError(R.string.fail_exportzip, e);
            targetFile = null;
        }
        if (targetFile != null)
            AlertSaveSuccess(targetFile);
    }

    /*private void SaveDisasm(DatabaseHelper disasmF) {
        new SaveDBAsync().execute(disasmF);
    }* /

    private void SaveDetailOld() {
        Log.v(TAG, "Saving details");
        File dir = new File(Environment.getExternalStorageDirectory().getPath() + "disasm/");
        File file = new File(dir, new File(fpath).getName() + "_" + new Date(System.currentTimeMillis()).toString() + ".details.txt");
        SaveDetail(dir, file);
    }
*/

}
