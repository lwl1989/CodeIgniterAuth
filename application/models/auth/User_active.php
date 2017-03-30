<?php
/**
 * Created by PhpStorm.
 * User: li
 * Date: 15-10-14
 * Time: 上午10:33
 */

class User_active extends CI_Model{

    private $table_name			= 'user_active';
    function __construct(){
        $ci =& get_instance();
        $this->table_name			= $ci->config->item('db_table_prefix', 'auth').$this->table_name;
        parent::__construct();
    }


    /**
     * 更新key
     *
     * @param $user_id
     * @param $old_email
     * @param $new_email
     * @param $active_key
     * @param $type
     * @return array|bool
     */
    function insert_new_key( $user_id , $old_email , $new_email , $active_key , $type ){

        $data = array(
            'user_id'           =>  $user_id,
            'type'              =>  $type,
            'old'               =>  $old_email,
            'new'               =>  $new_email,
            'key'               =>  $active_key,
            'create_task_time'  =>  date('Y-m-d H:m:s',time())
        );

        if ($this->db->insert($this->table_name, $data)) {
            $user_id = $this->db->insert_id();
            return array('user_id' => $user_id,'new_email'=>$new_email,'new_email_key'=>$active_key);
        }
        return FALSE;
    }

    /**
     *  获取key
     *
     * @param int $user_id
     * @param string $key
     * @param string $type | email_first,change_email,mobile_first,chang_mobile
     * @param int $expire_period
     * @return bool
     */
    function get_key( $user_id , $key , $type = 'email_first' , $expire_period = 172800 ){
        $this->db->select('1',false);  //select 1,  it is exits?  => select 1 from table..
        $this->db->where('user_id',$user_id);
        $this->db->where('key',$key);
        $this->db->where('UNIX_TIMESTAMP(create_task_time) <',time()-$expire_period);
        $this->db->where('type',$type);
        $query = $this->db->get($this->table_name);
        return $query->num_rows() == 1;
    }

    /**
     * 删除已激活的用户key，指定user_id和类型
     *
     * @param $user_id
     * @param $type
     */
    function del_key($user_id , $type){
        $this->db->where('user_id',$user_id);
        $this->db->where('type',$type);
        $this->db->delete($this->table_name);
    }

    /**
     * 删除
     *
     * @param $active_id
     */
    function del_key_by_id($active_id){
        $this->db->where('id',$active_id);
        $this->db->delete($this->table_name);
    }

    /**
     * 删除过时的key
     *
     * @param $expire_period
     */
    function del_key_expire($expire_period){
        $this->db->where('UNIX_TIMESTAMP(create_task_time) <',time()-$expire_period);
        $this->db->delete($this->table_name);
    }

    /**
     * 临时表更新新手机号（暂时使用session）
     *
     * @param $old
     * @param $new
     * @param $key
     * @return mixed
     */
    function update_new_mobile($old , $new , $key){
        $this->db->where('old',$old);
        $this->db->where('key',$key);
        $this->db->set('new',$new);
        $this->db->update($this->table_name);
        return $this->db->affected_rows();
    }

    /**
     * 检测用户能否更新密码（暂时使用session）
     *
     * @param $user_id
     * @param $old
     * @param $new
     * @param $key
     * @param $expire_period
     * @return bool
     */
    function can_change_mobile($user_id , $old , $new , $key , $expire_period){
        $this->db->select('1',false);
        $this->db->where('user_id',$user_id);
        $this->db->where('old',$old);
        $this->db->where('key',$key);
        $this->db->where('new',$new);
        $this->db->where('UNIX_TIMESTAMP(create_task_time) <',time()-$expire_period);
        $query = $this->db->get($this->table_name);
        return $query->num_rows() == 1;
    }

    /**
     * 检测这种形式的修改方式是否已存在了
     *
     * @param $user_id
     * @param $type
     * @return bool
     */
    function func_key_exists($user_id , $type){
        $this->db->select('id');
        $this->db->where('user_id' , $user_id);
        $this->db->where('type',$type);
        $query = $this->db->get($this->table_name);
        if ($query->num_rows() == 1) return $query->result_array()[0]['id'];
        return false;
    }

    /**
     * 检测email是否包含如下激活方式
     *
     * @param $email
     * @param $type
     * @return bool
     */
    function func_email_key_exists($email,$type){
        $this->db->select('id');
        $this->db->where('old' , $email);
        $this->db->where('type',$type);
        $query = $this->db->get($this->table_name);
        if ($query->num_rows() == 1) return $query->result_array()[0]['id'];
        return false;
    }

    /**
     * 能否重置密码
     *
     * @param $user_id
     * @param $expire_period
     * @return bool
     */
    function can_reset_password($user_id,$expire_period){
        $this->db->select('1',false);
        $this->db->where('user_id',$user_id);
        $this->db->where('UNIX_TIMESTAMP(create_task_time) <',time()-$expire_period);
        $query = $this->db->get($this->table_name);
        return $query->num_rows() == 1;
    }

    /**
     * 获取老邮箱
     *
     * @param $new
     * @param $key
     * @param $expire_period
     * @param $type
     * @return bool
     */
    function get_old_email($new,$key,$expire_period,$type = 'change_email'){
        $this->db->select('old');
        $this->db->where('new',$new);
        $this->db->where('key',$key);
        $this->db->where('type',$type);
        $this->db->where('UNIX_TIMESTAMP(create_task_time) <',time()-$expire_period);
        $query = $this->db->get($this->table_name);
        if ($query->num_rows() == 1) return $query->result_array()[0]['old'];
        return false;
    }
}