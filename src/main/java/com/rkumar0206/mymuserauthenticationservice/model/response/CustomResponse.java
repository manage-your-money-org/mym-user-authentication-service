package com.rkumar0206.mymuserauthenticationservice.model.response;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class CustomResponse<T> {

    private int status;
    private String message;
    private T body;
}
