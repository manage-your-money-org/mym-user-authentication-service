package com.rkumar0206.mymuserauthenticationservice.integration.stepDefinitions;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rkumar0206.mymuserauthenticationservice.model.response.CustomResponse;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

import java.io.IOException;

//@ContextConfiguration(classes = {MymUserAuthenticationServiceApplication.class}, loader = SpringBootContextLoader.class)
public class CreateUserSteps {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String BASE_URL = "https://localhost:8846/mym/api/users";
    private TestRestTemplate restTemplate = new TestRestTemplate();

    private ResponseEntity<CustomResponse> responseEntity;

    @When("User sends a POST request with valid {string}")
    public void user_sends_a_post_request_with(String requestBody) throws IOException {
/*        // Write code here that turns the phrase above into concrete actions
        File jsonFile = new File("src/test/resources/fixtures/" + requestBody);
        UserAccountRequest request = objectMapper.readValue(jsonFile, UserAccountRequest.class);

        responseEntity = restTemplate.postForEntity(BASE_URL + "/create", request, CustomResponse.class);
        UserAccountResponse response = (UserAccountResponse) responseEntity.getBody().getBody();

        System.out.println(response);*/
    }

    @Then("the response status code should be {int}")
    public void user_is_created_successfully(int responseStatusCode) {
        // Write code here that turns the phrase above into concrete actions
        //System.out.println("user_is_created_successfully");
    }
}
