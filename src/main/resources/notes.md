1、Spring Security的作用：
1-1、认证：
		包含模块：
		模块 						描述
		ACL 					支持通过访问控制列表(access control list,ACL)为域对象提供安全性
		切面(Aspects) 			一个很小的模块，当使用Spring Security注解时，会使用基于AspectJ的切面，而不是使用标准的Spring AOP
		CAS客户端（CAS Client） 	提供Jasig的中心认证服务（Central Authentication Service， CAS）进行集成的功能
		配置（Configuration） 		包含通过XML和Java配置Spring Security的功能支持
		核心（core） 				提供Spring Security基本库
		加密（Cryptography） 		提供加密和密码编码的功能
		LDAP 					支持基于LDAP进行认证
		OpenID 					支持使用OpenID进行集中式认证
		Remoting 				提供了对Spring Remoting的支持
		标签库(Tag Library) 		Spring Security的JSP标签库
		Web 					提供了Spring Security基于Filter的Web安全性支持
		
1-2、授权(访问控制)：通过访问控制授予不同的用户不同的权限

2、依赖配置：
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.thymeleaf.extras</groupId>
			<artifactId>thymeleaf-extras-springsecurity4</artifactId>
		</dependency>
		
3、Spring Security的使用：

3-1、security的配置类
		@EnableWebMvcSecurity
		public class SecurityWebApplicationInitializer extends AbstractSecurityWebApplicationInitializer {

		}
		
3-2、HttpSecurity
		protected void configure(HttpSecurity http) throws Exception {
			http
			.authorizeRequests()
			.anyRequest().authenticated() //确保我们应用中的所有请求都需要用户被认证
			.and()
			.formLogin()   //允许用户进行基于表单的认证
			.and()
			.httpBasic();  //允许用户使用HTTP基于验证进行认证
		}
		
3-3、表单登录
		protected void configure(HttpSecurity http) throws Exception {
			http
			.authorizeRequests()
			.anyRequest().authenticated()
			.and()
			.formLogin()
			.loginPage("/login") //指定登录页的路径
			.permitAll();  //允许用户访问所有登录页面  
			
			http.csrf().disable();//禁用CSRF防护功能   
		}
		
3-4、配置用户
		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth
			.inMemoryAuthentication()
			.withUser("user").password("password").roles("USER").and()  //配置用户的用户名 密码以及角色
			.withUser("admin").password("password").roles("USER", "ADMIN");
		}	
			
3-5、controller层代码
		@Controller
		public class LoginController {
			
			@RequestMapping(value="/login",method=RequestMethod.GET)  //指定的登录路径必须是login
			public String doLogin() {
				return "doLogin";   //跳转到登录页面
			}
			
			
			@RequestMapping(value="/",method=RequestMethod.GET)  //默认登录成功执行"/"路径
			public String result() {
				return "ok";
			}
		
4、方法总结：
	方法 											描述
	not() 										对其他访问方法的结果求反
	hasRole(String role) 						如果用户具备给定角色的话，就允许访问
	hasAnyRole(String… roles) 					如果用户具备给定角色中的某一个的话，就允许访问
	hasAuthority(String authority) 				如果用户具备给定权限的话，就允许访问
	hasAnyAuthority(String… authorities) 		如果用户具备给定权限中的某一个的话，就允许访问
	hasIpAddress(String ipaddressExpression) 	如果请求来自给定IP的话，就允许访问
	permitAll() 								无条件允许访问
	anonymous() 								允许匿名用户访问
	rememberMe() 								如果用户是通过Remember-me功能认证的，就允许访问
	denyAll() 									无条件拒绝所有访问
	authenticated() 							允许认证过的用户访问
	fullyAuthenticated() 						如果用户是完整认证的话(不是通过Remember-me功能认证的)，就允许访问
	access(String attribute) 					如果给定的spEl表达式计算结果为true，就允许访问	
	
