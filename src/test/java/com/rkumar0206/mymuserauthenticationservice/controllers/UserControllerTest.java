package com.rkumar0206.mymuserauthenticationservice.controllers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.rkumar0206.mymuserauthenticationservice.domain.UserAccount;
import com.rkumar0206.mymuserauthenticationservice.service.UserService;
import com.rkumar0206.mymuserauthenticationservice.utlis.JWT_Util;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@WebMvcTest(UserController.class)
@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;
    @MockBean
    private JWT_Util jwtUtil;

    @BeforeEach
    public void setup() {


    }

    @Test
    @WithMockUser(username = "user")
    void getUserByUid_UserIsAuthorized_Success() throws Exception {

        DecodedJWT decodedJWT = JWT.decode("eyJraWQiOiJmMDhhNDJhOS0wMDc2LTQ1ODAtODUzNy02NjcyY2ZhMTlmNWZBQ0NFU1NfVE9LRU4iLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJya3VtYXI4MDkyMzc4ODQ1QGdtYWlsLmNvbSIsInVpZCI6ImYxNmYyMjE5ZWViNjRlZGRhOTBmNjYxYTk0ZjZhNzM0IiwiaXNzIjoicm9oaXRUaGVCZXN0IiwibmFtZSI6IlJvaGl0IEt1bWFyIiwiZXhwIjoxNjkzNTcwMjEyLCJpYXQiOjE2OTM0ODM4MTJ9.JZq0hyM48J0AcAWFKNO95IzOHMUe_iryLzWVbilXy78");
        when(jwtUtil.isTokenValid(anyString())).thenReturn(decodedJWT);

        UserAccount userAccount = new UserAccount(
                "asnjknsk",
                "test@gmail.com",
                "asjbjhabhjavagvavgvvah",
                "rrrrrr",
                "Rohit Kumar",
                true,
                ""
        );


        when(userService.getUserByEmailId(anyString())).thenReturn(userAccount);
        when(userService.getUserByUid(anyString())).thenReturn(userAccount);

        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
                .get("/mym/api/users/details/uid")
                .param("uid", userAccount.getUid())
                .header("Authorization", "Bearer eyJraWQiOiJmMDhhNDJhOS0wMDc2LTQ1ODAtODUzNy02NjcyY2ZhMTlmNWZBQ0NFU1NfVE9LRU4iLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJya3VtYXI4MDkyMzc4ODQ1QGdtYWlsLmNvbSIsInVpZCI6ImYxNmYyMjE5ZWViNjRlZGRhOTBmNjYxYTk0ZjZhNzM0IiwiaXNzIjoicm9oaXRUaGVCZXN0IiwibmFtZSI6IlJvaGl0IEt1bWFyIiwiZXhwIjoxNjkzNTcwMjEyLCJpYXQiOjE2OTM0ODM4MTJ9.JZq0hyM48J0AcAWFKNO95IzOHMUe_iryLzWVbilXy78");


        MvcResult mvcResult = mockMvc.perform(requestBuilder)
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        assertEquals("{\"code\":200,\"message\":\"Success\",\"body\":{\"name\":\"Rohit Kumar\",\"emailId\":\"test@gmail.com\",\"uid\":\"rrrrrr\",\"accountVerified\":true}}", mvcResult.getResponse().getContentAsString());
    }

    @Test
    @WithMockUser(username = "user")
    void getUserByUid_UserIsAuthorized_UserTryingToAccessOtherAccount_403Response() throws Exception {

        DecodedJWT decodedJWT = JWT.decode("eyJraWQiOiJmMDhhNDJhOS0wMDc2LTQ1ODAtODUzNy02NjcyY2ZhMTlmNWZBQ0NFU1NfVE9LRU4iLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJya3VtYXI4MDkyMzc4ODQ1QGdtYWlsLmNvbSIsInVpZCI6ImYxNmYyMjE5ZWViNjRlZGRhOTBmNjYxYTk0ZjZhNzM0IiwiaXNzIjoicm9oaXRUaGVCZXN0IiwibmFtZSI6IlJvaGl0IEt1bWFyIiwiZXhwIjoxNjkzNTcwMjEyLCJpYXQiOjE2OTM0ODM4MTJ9.JZq0hyM48J0AcAWFKNO95IzOHMUe_iryLzWVbilXy78");
        when(jwtUtil.isTokenValid(anyString())).thenReturn(decodedJWT);

        UserAccount userAccount = new UserAccount(
                "asnjknsk",
                "test@gmail.com",
                "asjbjhabhjavagvavgvvah",
                "rrrrrr",
                "Rohit Kumar",
                true,
                ""
        );


        UserAccount otherUserAccount = new UserAccount(
                "", "test2@gmail.com", "dsbsb", "sjhbjshbjs", "Mohit Kumar", true, ""
        );

        when(userService.getUserByEmailId(anyString())).thenReturn(otherUserAccount);
        when(userService.getUserByUid(anyString())).thenReturn(userAccount);

        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
                .get("/mym/api/users/details/uid")
                .param("uid", userAccount.getUid())
                .header("Authorization", "Bearer eyJraWQiOiJmMDhhNDJhOS0wMDc2LTQ1ODAtODUzNy02NjcyY2ZhMTlmNWZBQ0NFU1NfVE9LRU4iLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJya3VtYXI4MDkyMzc4ODQ1QGdtYWlsLmNvbSIsInVpZCI6ImYxNmYyMjE5ZWViNjRlZGRhOTBmNjYxYTk0ZjZhNzM0IiwiaXNzIjoicm9oaXRUaGVCZXN0IiwibmFtZSI6IlJvaGl0IEt1bWFyIiwiZXhwIjoxNjkzNTcwMjEyLCJpYXQiOjE2OTM0ODM4MTJ9.JZq0hyM48J0AcAWFKNO95IzOHMUe_iryLzWVbilXy78");


        mockMvc.perform(requestBuilder)
                .andExpect(MockMvcResultMatchers.status().isForbidden())
                .andReturn();

    }


    @Test
    @WithMockUser(username = "user")
    void getUserByUid_UserIsAuthorized_UserNotFound_204Response() throws Exception {

        DecodedJWT decodedJWT = JWT.decode("eyJraWQiOiJmMDhhNDJhOS0wMDc2LTQ1ODAtODUzNy02NjcyY2ZhMTlmNWZBQ0NFU1NfVE9LRU4iLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJya3VtYXI4MDkyMzc4ODQ1QGdtYWlsLmNvbSIsInVpZCI6ImYxNmYyMjE5ZWViNjRlZGRhOTBmNjYxYTk0ZjZhNzM0IiwiaXNzIjoicm9oaXRUaGVCZXN0IiwibmFtZSI6IlJvaGl0IEt1bWFyIiwiZXhwIjoxNjkzNTcwMjEyLCJpYXQiOjE2OTM0ODM4MTJ9.JZq0hyM48J0AcAWFKNO95IzOHMUe_iryLzWVbilXy78");
        when(jwtUtil.isTokenValid(anyString())).thenReturn(decodedJWT);

        when(userService.getUserByEmailId(anyString())).thenReturn(null);
        when(userService.getUserByUid(anyString())).thenReturn(null);

        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
                .get("/mym/api/users/details/uid")
                .param("uid", "jshbsjhbjsbj")
                .header("Authorization", "Bearer eyJraWQiOiJmMDhhNDJhOS0wMDc2LTQ1ODAtODUzNy02NjcyY2ZhMTlmNWZBQ0NFU1NfVE9LRU4iLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJya3VtYXI4MDkyMzc4ODQ1QGdtYWlsLmNvbSIsInVpZCI6ImYxNmYyMjE5ZWViNjRlZGRhOTBmNjYxYTk0ZjZhNzM0IiwiaXNzIjoicm9oaXRUaGVCZXN0IiwibmFtZSI6IlJvaGl0IEt1bWFyIiwiZXhwIjoxNjkzNTcwMjEyLCJpYXQiOjE2OTM0ODM4MTJ9.JZq0hyM48J0AcAWFKNO95IzOHMUe_iryLzWVbilXy78");

        mockMvc.perform(requestBuilder)
                .andExpect(MockMvcResultMatchers.status().isNoContent())
                .andReturn();

    }


    @Test
    void getUserByUid_UserNotAuthorized_401Response() throws Exception {

        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
                .get("/mym/api/users/details/uid")
                .param("uid", "sbchjsbjh");

        mockMvc.perform(requestBuilder)
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andReturn();
    }


    @Test
    void createUser() {
    }

    @Test
    void verifyEmail() {
    }

    @Test
    void refreshToken() {
    }
}