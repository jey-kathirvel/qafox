<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;

Route::middleware('auth:sanctum')->prefix('api')->group(function () {
    Route::get('/books/{id}', function () {
        return [];
    });

    Route::post('/books', function () {
        request()->validate([
            'title' => 'required|string|min:2|max:80',
            'contact_email' => 'required|email',
            'author_id' => 'required|integer|min:1',
        ]);
        return [];
    });

    Route::apiResource('reviews', 'ReviewController');
});

class Book extends Model
{
    public function author()
    {
        return $this->belongsTo(Author::class);
    }
}
