package com.rkumar0206.mymuserauthenticationservice;

import org.springframework.boot.test.context.SpringBootContextLoader;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

@ContextConfiguration(classes = {MymUserAuthenticationServiceApplication.class}, loader = SpringBootContextLoader.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MymUserAuthenticationServiceApplicationTests {

//	@Test
//	void contextLoads() {
//	}
}
