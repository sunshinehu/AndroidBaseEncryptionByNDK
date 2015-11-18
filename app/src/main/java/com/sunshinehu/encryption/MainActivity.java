package com.sunshinehu.encryption;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

//com_sunshinehu_encryption_MainActivity

public class MainActivity extends Activity implements View.OnClickListener{

    private Button btn1;
    private Button btn2;

    private TextView text;

    private EditText edit;

    private RadioButton rb1,rb2,rb3,rb4;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        btn1= (Button) findViewById(R.id.button);
        btn2= (Button) findViewById(R.id.button2);
        text= (TextView) findViewById(R.id.textView);
        edit= (EditText) findViewById(R.id.editText);

        rb1= (RadioButton) findViewById(R.id.rb1);
        rb2= (RadioButton) findViewById(R.id.rb2);
        rb3= (RadioButton) findViewById(R.id.rb3);
        rb4= (RadioButton) findViewById(R.id.rb4);

        btn1.setOnClickListener(this);
        btn2.setOnClickListener(this);

    }



    @Override
    public void onClick(View view) {

        int flag=1;

        if(rb1.isChecked()){
            flag=1;
        }else if(rb2.isChecked()){
            flag=2;
        }else if(rb3.isChecked()){
            flag=3;
        }else if(rb4.isChecked()){
            flag=4;
        }

        if(view.getId()==R.id.button){
            switch (flag){
                case 1:
                    text.setText(EncryptionUtils.encodeMethod1(edit.getText().toString(), android.os.Build.SERIAL));
                    break;
                case 2:
                    text.setText(EncryptionUtils.encodeMethod2(edit.getText().toString()));
                    break;
                default:
                    Toast.makeText(this,"暂未提供",Toast.LENGTH_SHORT).show();
                    break;
            }
        }else if(view.getId()==R.id.button2){
            switch (flag){
                case 1:
                    text.setText(EncryptionUtils.decodeMethod1(edit.getText().toString(), android.os.Build.SERIAL));
                    break;
                case 2:
                    text.setText(EncryptionUtils.decodeMethod2(edit.getText().toString()));
                    break;
                default:
                    Toast.makeText(this,"暂未提供",Toast.LENGTH_SHORT).show();
                    break;
            }
        }
    }
}
