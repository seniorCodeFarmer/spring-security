package com.atguigu.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * @author zhangchengwei
 * @create 2022-10-11 11:14
 */
@Component
public class MyUserDetailService implements UserDetailsService {
    @Autowired
    private JdbcTemplate jdbcTemplate;
    // 总目标：根据表单提交的用户名查询user对象，并装配角色、权限等信息
    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        //1.使用 SQL 语句根据用户名查询用户对象
        String sql = "SELECT id,loginacct,userpswd,username,email,createtime FROM t_admin WHERE loginacct = ?";
        //2.获取查询结果
        Map<String, Object> resultMap = jdbcTemplate.queryForMap(sql, userName);
        //3.获取用户名、密码数据
        String loginacct = resultMap.get("loginacct").toString();
        String userpswd = resultMap.get("userpswd").toString();
        //4.创建权限列表
        List<GrantedAuthority> list = AuthorityUtils.createAuthorityList("ADMIN","USER");
        //5.创建用户对象
        User user = new User(loginacct, userpswd, list);
        return user;
    }
}
