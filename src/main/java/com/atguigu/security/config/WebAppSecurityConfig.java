package com.atguigu.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;

// 注意！这个类一定要放在自动扫描的包下，否则所有配置都不会生效！

// 将当前类标记为配置类
// 启用Web环境下权限控制功能
@Configuration
@EnableWebSecurity
public class WebAppSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private MyUserDetailService myUserDetailService;

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
//        builder.inMemoryAuthentication()
//                .withUser("tom") //在内存中完成帐号密码的检查
//                .password("123123")
//                .roles("ADMIN","学徒") // 指定当前用户的角色
//                .and()
//                .withUser("jerry")
//                .password("123123")
//                .authorities("UPDATE","内门弟子")
//                ;

        builder.userDetailsService(myUserDetailService);
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {

        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);

        httpSecurity.authorizeRequests() // 对请求进行授权
                .antMatchers("/index.jsp") // 针对/index.jsp路径进行授权
                .permitAll() // 可以无条件访问
                .antMatchers("/layui/**") // 针对/layui目录下所有资源进行授权
                .permitAll() // 可以无条件访问
                .antMatchers("/level1/**") // 针对/level1/**路径设置访问要求
                .hasRole("学徒")
                .antMatchers("/level2/**") // 针对/level2/**路径设置访问要求
                .hasAuthority("内门弟子") //要求用户具备内门弟子的权限才可以访问
                .and()
                .authorizeRequests() // 对请求进行授权
                .anyRequest() // 任意请求
                .authenticated() // 需要登录以后才可以访问
                .and()
                .formLogin() // 使用表单形式登录
                //关于loginPage()方法的特殊说明
                // 指定登录页的同时会影响到：“提交登录表单的地址、退出登录地址、登录失败地址”
                /**
                    // /index.jsp GET - the login form 去登录页面
                    // /index.jsp POST - process the credentials and if valid authenticate the user 提交登录表单
                    // /index.jsp?error GET - redirect here for failed authentication attempts 登录失败
                    // /index.jsp?logout GET - redirect here after successfully logging out 退出登录
                 */
                .loginPage("/index.jsp") // 指定登录页面，如果没有指定会访问springsecurity自带的登录页
                // loginProcessingUrl()方法指定了登录地址，就会覆盖loginPage()方法中设置的默认值/index.jsp POST
                .loginProcessingUrl("/do/login.html")	// 指定提交登录表单的地址
                .usernameParameter("loginAcct") // 登录帐号请求参数名
                .passwordParameter("userPswd") // 登录密码
                .defaultSuccessUrl("/main.html") // 登录成功后前往的地址
                .and()
//                .csrf()
//                .disable()  // 禁用CSRF功能
                .logout()  //开启退出功能
                .logoutUrl("/do/logout.html") // 指定处理退出请求的URL地址
                .logoutSuccessUrl("/index.jsp") // 退出成功后前往的地址
                .and()
                .exceptionHandling()
//                .accessDeniedPage("/to/no/auth/page.html") // 访问被拒绝前往的页面
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                        httpServletRequest.setAttribute("message","抱歉~您无法访问这个资源！");
                        httpServletRequest.getRequestDispatcher("/WEB-INF/views/no_auth.jsp").forward(httpServletRequest,httpServletResponse);
                    }
                })
                ;
    }
}
