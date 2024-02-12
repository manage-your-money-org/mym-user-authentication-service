package com.rkumar0206.mymuserauthenticationservice.integration.suites;

import io.cucumber.junit.Cucumber;
import io.cucumber.junit.CucumberOptions;
import org.junit.runner.RunWith;

@RunWith(Cucumber.class)
@CucumberOptions(
        glue = {"com/rkumar0206/mymuserauthenticationservice/integration/stepDefinitions"},
        features = "src/test/resources/features/createUser.feature",
        tags = "@integration",
        monochrome = true
)
public class UserTestRunner {
}
