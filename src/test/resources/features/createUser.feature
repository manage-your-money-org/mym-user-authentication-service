@integration
Feature: feature to test create user functionality

  Scenario Outline: Create new user with valid credentials
    When User sends a POST request with valid <request_body>
    Then the response status code should be <response_status>

    Examples:
      | request_body                           | response_status |
      | "create_new_user_request_valid.json"   | 200             |
      | "create_new_user_request_invalid.json" | 200             |
