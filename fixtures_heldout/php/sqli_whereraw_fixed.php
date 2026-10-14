<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class AccountLookupController extends Controller
{
    public function lookup(Request $request)
    {
        $email = $request->input('email');
        $user = User::whereRaw('email = ?', [$email])->first();

        return response()->json($user);
    }
}
