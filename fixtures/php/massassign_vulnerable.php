<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class RegisterController extends Controller
{
    public function store(Request $request)
    {
        // $request->all() may contain is_admin=1 sent by the client.
        $user = User::create($request->all());

        return response()->json($user);
    }
}
