<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class LoginRedirectController extends Controller
{
    public function after(Request $request)
    {
        $next = $request->query('next', '/dashboard');
        $allowed = ['/dashboard', '/profile', '/orders'];

        return redirect(in_array($next, $allowed, true) ? $next : '/dashboard');
    }
}
