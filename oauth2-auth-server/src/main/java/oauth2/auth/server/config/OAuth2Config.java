package oauth2.auth.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableAuthorizationServer
public class OAuth2Config extends AuthorizationServerConfigurerAdapter {
    @Autowired
    public PasswordEncoder passwordEncoder;

    @Autowired
    public UserDetailsService kiteUserDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenStore redisTokenStore;

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints)
        throws Exception {
        /**
         * redis token方式
         */
        endpoints
                //调用此方法支持password模式
                .authenticationManager(authenticationManager)
                //设置用户验证服务
                .userDetailsService(kiteUserDetailsService)
                //指定token的储存方式
                .tokenStore(redisTokenStore);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                //对应请求端定义的client-id
                .withClient("order-client")
                //对应请求端定义的client-secret
                .secret(passwordEncoder.encode("order-secret-8888"))
                //OAuth2授权模式
                .authorizedGrantTypes("refresh_token", "authorization_code", "password")
                //token的有效期
                .accessTokenValiditySeconds(3600)
                //用来限制客户端访问权限，在换取token的时候会带上scope参数，
                // 只有在 scopes 定义内的，才可以正常换取 token。
                .scopes("all")
                .and()
                .withClient("user-client")
                .secret(passwordEncoder.encode("user-secret-8888"))
                .authorizedGrantTypes("refresh_token", "authorization_code", "password")
                .accessTokenValiditySeconds(3600)
                .scopes("all");
    }

    /**
     * 此配置用于限制客户端访问认证接口的权限
     * 正确配置后，启动服务会暴露端口：/oauth/authorize; /oauth/token; /oauth/check_token
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //允许客户端访问OAuth2授权接口
        security.allowFormAuthenticationForClients();
        //允许已授权的用户访问checkToken接口
        security.checkTokenAccess("isAuthenticated()");
        //允许已授权的用户访问获取token接口
        security.tokenKeyAccess("isAuthenticated()");
    }
}
