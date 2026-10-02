package org.openresearchtools.torkitten;

import android.app.Activity;
import android.Manifest;
import android.content.pm.PackageManager;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.webkit.*;
import android.widget.TextView;
import android.widget.Toast;
import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import org.json.JSONObject;
import org.openresearchtools.torkitten.core.mobile.Core;
import org.openresearchtools.torkitten.core.mobile.Mobile;

/* Only bundled app pages get this bridge. Service URLs never load here. */
public final class MainActivity extends Activity {
    private static final String ORIGIN="https://appassets.androidplatform.net";
    private static final String CSP="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; frame-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'none'";
    private static final String ADAPTER="const pending=new Map();let sequence=0;window.__nativeComplete=(id,r)=>{let p=pending.get(id);pending.delete(id);if(r.error)p.reject(new Error(r.error));else p.resolve(new Response([204,205,304].includes(r.status)?null:Uint8Array.from(atob(r.body),c=>c.charCodeAt(0)),{status:r.status,headers:{'Content-Type':r.type}}));};window.fetch=(url,o={})=>new Promise((resolve,reject)=>{let u=new URL(url,location.href);if(u.origin!==location.origin){reject(new Error('External network denied'));return;}let id=++sequence;pending.set(id,{resolve,reject});Native.request(id,o.method||'GET',u.pathname+u.search,o.body||'');});";
    private final ExecutorService executor=Executors.newSingleThreadExecutor();
    private Core core;
    private WebView web;
    private ValueCallback<Uri[]> files;
    private byte[] pendingSave;
    private PermissionRequest cameraRequest;
    private boolean stopped;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView loading=new TextView(this);loading.setText("Starting TorKitten…");setContentView(loading);
        executor.execute(()->{
            try {
                Core opened=Mobile.open(getFilesDir().getAbsolutePath(),getApplicationInfo().nativeLibraryDir);
                runOnUiThread(()->{if(stopped){try{opened.close();}catch(Exception ignored){}}else{core=opened;openUI();}});
            } catch(Exception error) {
                runOnUiThread(()->loading.setText("TorKitten could not start. Its packaged Tor runtime is required."));
            }
        });
    }
    private void openUI() {
        web=new WebView(this);
        WebView.setWebContentsDebuggingEnabled(false);
        WebSettings settings=web.getSettings();settings.setJavaScriptEnabled(true);
        settings.setBlockNetworkLoads(true);settings.setAllowFileAccess(false);settings.setAllowContentAccess(false);
        settings.setDatabaseEnabled(false);settings.setDomStorageEnabled(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.addJavascriptInterface(new Bridge(),"Native");
        web.setWebViewClient(new WebViewClient(){
            @Override public boolean shouldOverrideUrlLoading(WebView view,WebResourceRequest request){return !local(request.getUrl());}
            @Override public WebResourceResponse shouldInterceptRequest(WebView view,WebResourceRequest request){
                if(!local(request.getUrl()) || !"GET".equals(request.getMethod()))return denied();
                String path=request.getUrl().getEncodedPath();
                if(request.getUrl().getEncodedQuery()!=null)path+="?"+request.getUrl().getEncodedQuery();
                try {
                    if(path.equals("/native.js"))return response(200,"text/javascript",ADAPTER.getBytes(StandardCharsets.UTF_8));
                    JSONObject r=new JSONObject(core.request("GET",path,""));
                    byte[] body=Base64.decode(r.getString("body"),Base64.DEFAULT);
                    if(path.equals("/"))body=new String(body,StandardCharsets.UTF_8).replace("<head>","<head><script src=\"/native.js\"></script>").getBytes(StandardCharsets.UTF_8);
                    return response(r.getInt("status"),r.getString("type"),body);
                }catch(Exception error){return denied();}
            }
        });
        web.setWebChromeClient(new WebChromeClient(){
            @Override public void onPermissionRequest(PermissionRequest request){runOnUiThread(()->{
                if(stopped || cameraRequest!=null || !cameraOnly(request)){request.deny();return;}
                if(checkSelfPermission(Manifest.permission.CAMERA)==PackageManager.PERMISSION_GRANTED)request.grant(new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
                else{cameraRequest=request;requestPermissions(new String[]{Manifest.permission.CAMERA},3);}
            });}
            @Override public void onPermissionRequestCanceled(PermissionRequest request){runOnUiThread(()->{if(cameraRequest==request)cameraRequest=null;});}
            @Override public boolean onShowFileChooser(WebView view,ValueCallback<Uri[]> callback,FileChooserParams params){
                if(files!=null)files.onReceiveValue(null);files=callback;
                try{startActivityForResult(params.createIntent(),1);}catch(Exception e){files.onReceiveValue(null);files=null;}
                return true;
            }
        });
        setContentView(web);web.loadUrl(ORIGIN+"/");
    }
    private boolean cameraOnly(PermissionRequest request){
        String origin=request.getOrigin().toString();String[] resources=request.getResources();
        return web!=null && web.getUrl()!=null && local(Uri.parse(web.getUrl())) &&
            (ORIGIN.equals(origin) || (ORIGIN+"/").equals(origin)) && resources.length==1 && PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(resources[0]);
    }
    @Override public void onRequestPermissionsResult(int request,String[] permissions,int[] results){
        super.onRequestPermissionsResult(request,permissions,results);
        if(request==3 && cameraRequest!=null){
            PermissionRequest pending=cameraRequest;cameraRequest=null;
            if(!stopped && permissions.length==1 && Manifest.permission.CAMERA.equals(permissions[0]) && results.length==1 && results[0]==PackageManager.PERMISSION_GRANTED && cameraOnly(pending))pending.grant(new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
            else pending.deny();
        }
    }
    private static boolean local(Uri u){return "https".equals(u.getScheme()) && "appassets.androidplatform.net".equals(u.getHost()) && u.getPort()==-1 && u.getUserInfo()==null;}
    private static WebResourceResponse response(int status,String type,byte[] body){
        HashMap<String,String> headers=new HashMap<>();headers.put("Content-Type",type);headers.put("Content-Security-Policy",CSP);headers.put("Cache-Control","no-store");headers.put("X-Content-Type-Options","nosniff");
        return new WebResourceResponse(type.split(";",2)[0],"UTF-8",status,"Local API",headers,new ByteArrayInputStream(body));
    }
    private static WebResourceResponse denied(){return response(403,"text/plain",new byte[0]);}
    private final class Bridge {
        @JavascriptInterface public void save(String name,String encoded){
            if(encoded.length()>1400000 || !name.matches("[A-Za-z0-9_.-]{1,80}\\.age"))return;
            final byte[] bytes;
            try{bytes=Base64.decode(encoded,Base64.DEFAULT);}catch(IllegalArgumentException e){return;}
            if(!new String(bytes,0,Math.min(bytes.length,23),StandardCharsets.US_ASCII).startsWith("age-encryption.org/v1\n"))return;
            runOnUiThread(()->{
                if(stopped || pendingSave!=null)return;
                pendingSave=bytes;
                Intent create=new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE,name);
                startActivityForResult(create,2);
            });
        }
        @JavascriptInterface public void request(int id,String method,String path,String body){
            executor.execute(()->{
                String result;
                try{result=core.request(method,path,body);}catch(Exception e){result="{\"error\":\"Private API request failed\"}";}
                final String json=result;
                runOnUiThread(()->{if(web!=null)web.evaluateJavascript("window.__nativeComplete("+id+","+json+")",null);});
            });
        }
    }
    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);
        if(request==2 && pendingSave!=null){
            byte[] bytes=pendingSave;pendingSave=null;
            if(result==RESULT_OK && data!=null && data.getData()!=null){
                Uri destination=data.getData();
                executor.execute(()->{try(OutputStream stream=getContentResolver().openOutputStream(destination,"wt")){if(stream==null)throw new java.io.IOException();stream.write(bytes);}catch(Exception e){runOnUiThread(()->Toast.makeText(this,"Encrypted file could not be saved",Toast.LENGTH_LONG).show());}finally{Arrays.fill(bytes,(byte)0);}});
            }else Arrays.fill(bytes,(byte)0);
        }
        if(request==1 && files!=null){files.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(result,data));files=null;}
    }
    @Override protected void onStop(){
        super.onStop();
        if(cameraRequest!=null){cameraRequest.deny();cameraRequest=null;}
        if(web!=null)web.evaluateJavascript("(()=>{if(typeof stopCamera==='function')stopCamera();const d=document.getElementById('scan-dialog');if(d&&d.open)d.close();})()",null);
    }
    @Override protected void onDestroy(){
        stopped=true;
        if(cameraRequest!=null){cameraRequest.deny();cameraRequest=null;}
        if(pendingSave!=null){Arrays.fill(pendingSave,(byte)0);pendingSave=null;}
        if(web!=null){web.removeJavascriptInterface("Native");web.destroy();web=null;}
        executor.execute(()->{if(core!=null)try{core.close();}catch(Exception ignored){}});executor.shutdown();super.onDestroy();
    }
}
