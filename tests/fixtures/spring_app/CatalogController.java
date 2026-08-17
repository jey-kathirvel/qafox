package com.example.catalog;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

class ItemRequest {
    @NotBlank
    @Size(min = 2, max = 80)
    private String title;

    @Email
    private String contactEmail;

    @Min(1)
    private Integer publisherId;
}

@RestController
@RequestMapping("/v1/catalog")
public class CatalogController {
    @GetMapping("/items/{id}")
    public String getItem(
            @PathVariable Long id,
            @RequestParam(required = false) String q,
            @RequestHeader(required = false) String xRequestId
    ) {
        return "{}";
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/items")
    public String createItem(@RequestBody ItemRequest body) {
        return "{}";
    }
}
