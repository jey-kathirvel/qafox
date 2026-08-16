package com.example.catalog;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/catalog")
public class CatalogController {
    @GetMapping("/items/{id}")
    public String getItem() {
        return "{}";
    }
}
