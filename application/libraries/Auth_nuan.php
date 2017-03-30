<?php

/**
 * Created by PhpStorm.
 * User: li
 * Date: 15-10-13
 * Time: 上午10:58
 */
require_once('phpass-0.1/PasswordHash.php');

define('STATUS_ACTIVATED', '1');
define('STATUS_NOT_ACTIVATED', '0');
class Auth_nuan
{
    private $error = array();

    function __construct(){
        $this->ci =& get_instance();

        $this->ci->load->config('auth', TRUE);

        $this->ci->load->library('session');
        $this->ci->load->database();
        $this->ci->load->model('auth/users');
        $this->ci->load->model('auth/user_active');
        $this->autologin();
    }

    function get_error(){
        return $this->error;
    }
    /**
     * @param bool|TRUE $activated
     * @return bool
     */
    function is_logged_in($activated = TRUE)
    {
        $user = @$_SESSION['login_user'];
        return $user['status'] === ($activated ? STATUS_ACTIVATED : STATUS_NOT_ACTIVATED);
    }

    /**
     * @return bool
     */
    function autologin(){

        if(!$this->is_logged_in() and !$this->is_logged_in(FALSE)){
            $this->ci->load->helper('cookie');
            if ($cookie = get_cookie($this->ci->config->item('autologin_cookie_name', 'auth'), TRUE)) {

                $data = unserialize($cookie);

                if (isset($data['key']) AND isset($data['user_id'])) {

                    $this->ci->load->model('auth/user_autologin');
                    if (!is_null($user = $this->ci->user_autologin->get($data['user_id'], md5($data['key'])))) {
                        // Login user
                       $_SESSION['login_user']= array(
                            'user_id'	=> $user->id,
                            'username'	=> $user->username,
                            'email'     => $user->email,
                            'mobile'    => $user->mobile,
                            'status'	=> STATUS_ACTIVATED,
                        );

                        // Renew users cookie to prevent it from expiring
                        set_cookie(array(
                            'name' 		=> $this->ci->config->item('autologin_cookie_name', 'auth'),
                            'value'		=> $cookie,
                            'expire'	=> $this->ci->config->item('autologin_cookie_life', 'auth'),
                        ));

                       $this->ci->users->update_login_info(
                            $user->id,
                            $this->ci->config->item('login_record_ip', 'auth'),
                            $this->ci->config->item('login_record_time', 'auth'));

                        return TRUE;
                    }
                }
            }
        }
        return FALSE;
    }

    /**
     * @param $user_id
     * @return bool
     */
    public function create_autologin($user_id)
    {
        $this->ci->load->helper('cookie');
        $key = substr(md5(uniqid(rand().get_cookie($this->ci->config->item('sess_cookie_name')))), 0, 16);

        $this->ci->load->model('auth/user_autologin');
        $this->ci->user_autologin->purge($user_id);

        if ($this->ci->user_autologin->set($user_id, md5($key))) {
            set_cookie(array(
                'name' 		=> $this->ci->config->item('autologin_cookie_name', 'auth'),
                'value'		=> serialize(array('user_id' => $user_id, 'key' => $key)),
                'expire'	=> $this->ci->config->item('autologin_cookie_life', 'auth'),
            ));
            return TRUE;
        }
        return FALSE;
    }


    /**
     * 登录操作
     *
     * @param   string
     * @param   string
     * @param   bool
     * @param   bool
     * @param   bool
     * @return	bool
     */
    function login($login, $password, $remember, $login_by_email = false ){
        if ((strlen($login) > 0) AND (strlen($password) > 0) ) {
            if ($login_by_email) {
                $get_user_func = 'get_user_by_email';
            } else {
                $get_user_func = 'get_user_by_mobile';
            }
            if (!is_null($user = $this->ci->users->$get_user_func($login))) {
                $hasher = new PasswordHash(
                    $this->ci->config->item('phpass_hash_strength', 'auth'),
                    $this->ci->config->item('phpass_hash_portable', 'auth'));

                //密码正确
                if ($hasher->CheckPassword($password, $user->password)) {
                    if ($user->banned == 1) {                                    // 用户被禁止？
                        $this->error = array('banned' => $user->ban_reason);
                    } else {
                        $_SESSION['login_user'] = array(
                            'user_id' => $user->id,
                            'username' => $user->username,
                            'email' => $user->email,
                            'mobile' => $user->mobile,
                            'status' => ($user->activated == 1) ? STATUS_ACTIVATED : STATUS_NOT_ACTIVATED,
                        );
                        // 没有激活
                        if ($user->activated == 0) {
                            $this->error = array('not_activated' => '');
                        }
                        if ($remember) {
                            $this->create_autologin($user->id);
                        }

                        $this->clear_login_attempts($login);

                        $this->ci->users->update_login_info(
                            $user->id,
                            $this->ci->config->item('login_record_ip', 'auth'),
                            $this->ci->config->item('login_record_time', 'auth'));
                        return TRUE;

                    }
                }else{
                    $this->increase_login_attempt($login);
                    $this->error = array('password' => '密码错误');
                }
            }
            else {
                $this->increase_login_attempt($login);
                $this->error = array('login' => '账号不存在');
            }
        }
        return FALSE;
    }

    /**
     * 退出登录
     *
     */
    function logout()
    {
        $this->delete_autologin();
        unset($_SESSION['login_user']);
        session_destroy();
    }
    /**
     * 获取ID
     *
     * @return	string
     */
    function get_user_id()
    {
        $user = $_SESSION['login_user'];
        return $user['user_id'];
    }

    /**
     * 获取用户名
     *
     * @return	string
     */
    function get_username()
    {
        $user = $_SESSION['login_user'];
        return $user['username'];
    }

    /**
     * 获取手机
     *
     * @return	string
     */
    function get_mobile()
    {
        $user = $_SESSION['login_user'];
        return $user['mobile'];
    }
    /**
     * 获取邮箱
     *
     * @return	string
     */
    function get_email()
    {
        $user = $_SESSION['login_user'];
        return $user['email'];
    }
    /**
     * 创建一个新用户
     *
     * @param	string
     * @param	string ['mobile','email']
     * @param	string
     * @param	string
     * @param	array
     * @return	array
     */
    function create_user($username, $type , $account , $password ,$extend = [])
    {
        if($type!='email' && $type!='mobile') {
            $this->error = array('type' => '帐户类型暂不支持');
        }else{
            $fun = 'is_'.$type.'_available';
            if ((strlen($username) > 0) AND !$this->ci->users->is_username_available($username)) {
                $this->error = array('username' => '该用户名已注册');

            } elseif (!$this->ci->users->$fun($account) AND $account) {
                $this->error = array($type => '该'.(($type=='email')?'邮箱':'手机号').'已注册');

            } else {

                $hasher = new PasswordHash(
                    $this->ci->config->item('phpass_hash_strength', 'tank_auth'),
                    $this->ci->config->item('phpass_hash_portable', 'tank_auth'));
                $hashed_password = $hasher->HashPassword($password);

                $data = array(
                    'username'	=> $username,
                    'password'	=> $hashed_password,
                    $type		=> $account,
                    'last_ip'	=> $this->ci->input->ip_address(),
                );

                if ($type == 'email') {
                    $new_email_key = md5(rand().microtime());
                }
                $data = array_merge($data, $extend);
                if (!is_null($res = $this->ci->users->create_user($data, false))) {

                    $this->has_key_exists($res['user_id'],'email_first');
                    $this->ci->user_active->insert_new_key(
                        $res['user_id'],$account,NULL,$new_email_key,'email_first');
                    $data['user_id'] = $res['user_id'];
                    $data['password'] = $password;
                    unset($data['last_ip']);
                    return $data;
                }
            }
        }
        return NULL;
    }

    /**
     * 检测用户名是否可用
     *
     * @param	string
     * @return	bool
     */
    function is_username_available($username)
    {
        return ((strlen($username) > 0) AND $this->ci->users->is_username_available($username));
    }

    /**
     * 检测邮箱是否可用
     *
     * @param	string
     * @return	bool
     */
    function is_email_available($email)
    {
        return ((strlen($email) > 0) AND $this->ci->users->is_email_available($email));
    }

    /**
     * 检测手机是否可用
     *
     * @param	string
     * @return	bool
     */
    function is_mobile_available($mobile)
    {
        return ((strlen($mobile) > 0) AND $this->ci->users->is_mobile_available($mobile));
    }

    /**
     * 修改用户绑定邮箱/手机:
     * 返回数组：user_id, username, old, new.
     *
     * @param	string
     * @return	array
     */
    function change_email($account)
    {
        $user_id = $this->get_user_id();

        if (!is_null($user = $this->ci->users->get_user_by_id($user_id))) {

            $data = array(
                'username'	=> $user->username,
            );

            if ($this->is_email_available($account)) {
                $new_key = md5(rand().microtime());

                $this->has_key_exists($user_id,'change_email');
                array_merge($data,$this->ci->user_active->insert_new_key(
                    $user_id,$user->email,$account,$new_key,'change_email'));
                //$this->del_key_exists($user_id,'change_email');
                return $data;
            } else {
                $this->error = array('email' => '该邮箱已注册');
            }
        }
        return NULL;
    }

    /**
     * 在修改手机绑定之前，要先进行手机验证
     *
     * @return bool
     */
    function before_change_mobile(){
        $user_id = $this->get_user_id();
        if($user_id){
            $mobile = $_SESSION['login_user']['mobile'];
            $code = $this->send_verify($mobile);
            $_SESSION['mobile_change'] = array(
                'user_id'   =>  $user_id,
                'old'=> $mobile,
                'new' => NULL,
                'key'=>$code
            );
            return TRUE;
        }
        return FALSE;
    }

    /**
     * 验证更改手机的验证码
     *
     * @param $code
     * @return bool
     */
    function verify_mobile_change($code){
        $mobile = $this->get_mobile();
        $user_id = $this->get_user_id();
        $verify_info = $_SESSION['mobile_change'];
        if($verify_info['key']==$code){
            unset($_SESSION['mobile_verify']);
            $this->has_key_exists($user_id,'change_mobile');
            return $this->ci->User_active->insert_new_key(
                $user_id,$mobile,'',md5($code),'change_mobile');
        }
        return FALSE;
    }

    /**
     * 验证新手机并且更新session
     *
     * @param $new_mobile
     * @param $code
     */
    function verify_new_mobile($new_mobile,$code){
        if(!$this->verify_code($new_mobile,$code)){
            $this->error = array('verify'=>'验证码错误');
        }
        $data = $_SESSION['mobile_change'];
        $data['new_mobile'] = $new_mobile;
        $_SESSION['mobile_change'] = $data;
        $this->ci->user_active->update_new_mobile($data['old'],$data['new'],$data['key']);
    }

    /**
     * 更改手机号
     *
     */
    function change_mobile(){
        $user_id = $this->get_user_id();
        if(isset($_SESSION['mobile_change'])){
            $data = $_SESSION['mobile_change'];
            if($this->ci->user_active->can_mobile__change(
                $data['user_id'],$data['old'],$data['new'],$data['key'])) {
                return $this->ci->users->change_mobile($user_id,$data['mobile']);
            }
        }
        return false;
    }
    /**
     * 激活用户
     *
     * @param	string
     * @param	string
     * @param	string | email_first,change_email
     * @return	bool

    function activate_user($user_id, $activation_key, $func)
    {
        //将超时未激活的用户删除
        $this->ci->users->purge_na($this->ci->config->item('email_activation_expire', 'auth'));

        if ((strlen($user_id) > 0) AND (strlen($activation_key) > 0)) {
            if($this->ci->user_active->get_key($user_id,$activation_key,$func)){
                return $this->ci->users->activate_user($user_id, $activation_key, $func);
            }
        }
        return FALSE;
    } */


    /**
     * 发送验证码
     *
     * @param $mobile
     * @return bool
     */
    function send_verify($mobile)
    {
        if(isset($_SESSION['mobile_verify'])){
            $this->error = array('msg'=>'太快的请求发送验证码');
        }else{
            $this->ci->session->mark_as_temp('mobile_verify',60);
            $this->ci->load->helper('sms');//加载短信发送方法
            $this->ci->load->helper('verify');
            $verify_code=rand_pass();
            $flag=send_sms($mobile,$verify_code,'register',true);  //最后一个参数测试时改为true或者去掉
            if($flag){
                $_SESSION['sms_verify'] = array('mobile'=>$mobile,'verify'=>md5($verify_code));
                return $verify_code;
            }else{
                unset($_SESSION['mobile_verify']);
                $this->error = array('msg'=>'发送短信失败');
            }
        }
        return FALSE;
    }


    /**
     * 验证短信
     *
     * @param $mobile
     * @param $code
     * @return array|bool
     */
    function verify_code($mobile,$code){
        if(isset($_SESSION['mobile_verify'])){
            $session_verify = $_SESSION['mobile_verify'];
            if($session_verify['mobile'] == $mobile AND $session_verify['code'] == md5($code)){
                unset($_SESSION['mobile_verify']);
                return array('mobile',$mobile);
            }
        }
        return FALSE;
    }

    /**
     * 手机激活用户
     *
     * @param $mobile
     * @param $code
     */
    function mobile_active($mobile,$code){
        if(strlen($mobile)>0 and strlen($code)>0){
            if($this->verify_code($mobile,$code)){
                $this->ci->users->activate_user_by_mobile($mobile);
            }
        }
    }

    /**
     * 邮箱激活
     *
     * @param $email
     * @param $key
     * @param bool|true $first
     * @return bool
     */
    function email_active($email,$key,$first = true){
        if(strlen($email)>0 and strlen($key)>0){
            $type_str = $first?'email_first':'change_email';
            if(!$first){
                $old_email = $this->ci->user_active->get_old_email($email,$key,'change_email');
                if(!$old_email){
                    $this->error = array('key' , '无法定位您的主帐户，请重新申请发送邮件');
                    return false;
                }
                $this->ci->users->change_email($email,$old_email);
            }else{
                if(!$this->has_key_exists_by_email($email,"email_first")){
                    $this->error = array('key' , '激活key不存在,请申请发送邮件');
                    return false;
                }
            }
            $user = $this->ci->users->get_user_by_email($email);
            $this->ci->users->activate_user($user->id);
            $_SESSION['login_user'] = array(
                'user_id' => $user->id,
                'username' => $user->username,
                'email' => $user->email,
                'mobile' => $user->mobile,
                'status' => ($user->activated == 1) ? STATUS_ACTIVATED : STATUS_NOT_ACTIVATED,
            );
            $this->del_key_exists($user->id,$type_str);
            return true;
        }
        return false;
    }



    /**
     *
     * 当用户忘记密码时，输入帐户，生成临时的key
     *
     * @param	string
     * @param   string
     * @return	array
     */
    function forgot_password($login)
    {
        if (strlen($login) > 0) {
            if (!is_null($user = $this->ci->users->get_user_by_login($login))) {

                $data = array(
                    'user_id'		=> $user->id,
                    'username'		=> $user->username,
                    'email'			=> $user->email,
                    'new_pass_key'	=> md5(rand().microtime()),
                );
                $this->has_key_exists($user->id,'change_pass');
                $this->ci->user_active->insert_new_key($user->id, $login,NULL,$data['new_pass_key'],'change_pass');
                return $data;

            } else {
                $this->error = array('login' => 'auth_incorrect_email_or_username');
            }
        }
        return NULL;
    }


    /**
     * 重置密码
     *
     * @param $user_id
     * @param $new_pass_key
     * @param $new_password
     * @return bool
     * @internal param $string
     * @internal param $string
     */
    function reset_password($user_id, $new_pass_key, $new_password)
    {
        if ((strlen($user_id) > 0) AND (strlen($new_pass_key) > 0) AND (strlen($new_password) > 0)) {

            if (!is_null($user = $this->ci->users->get_user_by_id($user_id, TRUE))) {

                if($this->can_reset_password($user_id,$new_pass_key)){
                    $hasher = new PasswordHash(
                        $this->ci->config->item('phpass_hash_strength', 'tank_auth'),
                        $this->ci->config->item('phpass_hash_portable', 'tank_auth'));
                    $hashed_password = $hasher->HashPassword($new_password);

                    $this->ci->users->change_password($user_id,$hashed_password);

                    $this->ci->load->model('tank_auth/user_autologin');
                    $this->ci->user_autologin->clear($user->id);

                    $this->del_key_exists($user_id,'change_pass');
                    return array(
                        'user_id'		=> $user_id,
                        'username'		=> $user->username,
                        'email'			=> $user->email,
                        'new_password'	=> $new_password,
                    );
                }


            }
        }
        return NULL;
    }
    /**
     * 检测key是否存在，存在删除重写
     *
     * @param $user_id
     * @param $type
     */
    private function has_key_exists($user_id,$type){
        $active_id = $this->ci->user_active->func_key_exists($user_id,$type);
        if($active_id){
            $this->ci->user_active->delete_active($user_id,$type);
        }
    }

    private function has_key_exists_by_email($email,$type){
        $active_id = $this->ci->user_active->func_email_key_exists($email,$type);
        if($active_id){
            return $active_id;
        }
        return false;
    }


    /**
     * 删除key
     *
     * @param $user_id
     * @param $type
     */
    private function del_key_exists($user_id,$type){
        $this->ci->user_active->del_key($user_id,$type);
    }
    /**
     * 删除自动登录
     */
    private function delete_autologin()
    {
        $this->ci->load->helper('cookie');
        if ($cookie = get_cookie($this->ci->config->item('autologin_cookie_name', 'auth'), TRUE)) {

            $data = unserialize($cookie);

            $this->ci->load->model('auth/user_autologin');
            $this->ci->user_autologin->delete($data['user_id'], md5($data['key']));

            delete_cookie($this->ci->config->item('autologin_cookie_name', 'auth'));
        }
    }

    /**
     * 记录错误的登录次数
     *
     * @param string
     */
    private function increase_login_attempt($login)
    {
        if ($this->ci->config->item('login_count_attempts', 'auth')) {
            if (!$this->is_max_login_attempts_exceeded($login)) {
                $this->ci->load->model('tank_auth/login_attempts');
                $this->ci->login_attempts->increase_attempt($this->ci->input->ip_address(), $login);
            }
        }
    }
    /**
     * 清除错误登录次数
     *
     *  @param string
     */
    private function clear_login_attempts($login)
    {
        if ($this->ci->config->item('login_count_attempts', 'tank_auth')) {
            $this->ci->load->model('tank_auth/login_attempts');
            $this->ci->login_attempts->clear_attempts(
                $this->ci->input->ip_address(),
                $login,
                $this->ci->config->item('login_attempt_expire', 'tank_auth'));
        }
    }
    /**
     * 检测是否能修改密码
     *
     * @param	string
     * @param	string
     * @return	bool
     */
    private function can_reset_password($user_id, $new_pass_key)
    {
        if ((strlen($user_id) > 0) AND (strlen($new_pass_key) > 0)) {
            return $this->ci->user_active->can_reset_password(
                $user_id,
                $new_pass_key,
                $this->ci->config->item('forgot_password_expire', 'auth'));
        }
        return FALSE;
    }

    /**
     * 检测用户是否超过最多登录次数
     *
     * @param	string
     * @return	bool
     */
    function is_max_login_attempts_exceeded($login)
    {
        if ($this->ci->config->item('login_count_attempts', 'tank_auth')) {
            $this->ci->load->model('tank_auth/login_attempts');
            return $this->ci->login_attempts->get_attempts_num($this->ci->input->ip_address(), $login)
            >= $this->ci->config->item('login_max_attempts', 'tank_auth');
        }
        return FALSE;
    }

}