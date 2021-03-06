<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

//Route::middleware('auth:api')->get('/user', function (Request $request) {
//    return $request->user();
//});

Route::post('register', [UserController::class, 'create']);
Route::post('login', [UserController::class, 'login']);
Route::group(['middleware' => ['jwt.verify']], function() {
    Route::post('user', [UserController::class, 'getAuthenticatedUser']);
});

Route::prefix('users')->group(function () {
    Route::get('all', [UserController::class, 'index']);
    Route::get('get/{id}', [UserController::class, 'show']);
    Route::put('update/{id}', [UserController::class, 'update']);
    Route::delete('deleted/{id}', [UserController::class, 'destroy']);
});
