/**
 * 
 */
package com.qz.security.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.social.security.SpringSocialConfigurer;

import com.qz.security.app.authentication.openid.OpenIdAuthenticationSecurityConfig;
import com.qz.security.core.authentication.mobile.SmsCodeAuthenticationSecurityConfig;
import com.qz.security.core.properties.SecurityConstants;
import com.qz.security.core.properties.SecurityProperties;
import com.qz.security.core.validate.code.ValidateCodeSecurityConfig;

/**
 * @author yb
 *
 */
@Configuration
@EnableResourceServer
public class QzResourceServerConfig extends ResourceServerConfigurerAdapter {
	
	@Autowired
	protected AuthenticationSuccessHandler qzAuthenticationSuccessHandler;
	
	@Autowired
	protected AuthenticationFailureHandler qzAuthenticationFailureHandler;
	
	@Autowired
	private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;
	
	@Autowired
	private OpenIdAuthenticationSecurityConfig openIdAuthenticationSecurityConfig;
	
	@Autowired
	private ValidateCodeSecurityConfig validateCodeSecurityConfig;
	
	@Autowired
	private SpringSocialConfigurer imoocSocialSecurityConfig;
	
	@Autowired
	private SecurityProperties securityProperties;
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		
		http.formLogin()
			.loginPage(SecurityConstants.DEFAULT_UNAUTHENTICATION_URL)
			.loginProcessingUrl(SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_FORM)
			.successHandler(qzAuthenticationSuccessHandler)
			.failureHandler(qzAuthenticationFailureHandler);
		
		http.apply(validateCodeSecurityConfig)
				.and()
			.apply(smsCodeAuthenticationSecurityConfig)
				.and()
			.apply(imoocSocialSecurityConfig)
				.and()
			.apply(openIdAuthenticationSecurityConfig)
				.and()
			.authorizeRequests()
				.antMatchers(
					SecurityConstants.DEFAULT_UNAUTHENTICATION_URL,
					SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_MOBILE,
					SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_OPENID,
					securityProperties.getBrowser().getLoginPage(),
					SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX+"/*",
					securityProperties.getBrowser().getSignUpUrl(),
					securityProperties.getBrowser().getSession().getSessionInvalidUrl(),
					securityProperties.getBrowser().getSignOutUrl(),
					"/user/regist", "/social/signUp")
					.permitAll()
				.anyRequest()
				.authenticated()
				.and()
			.csrf().disable();
	}

}
