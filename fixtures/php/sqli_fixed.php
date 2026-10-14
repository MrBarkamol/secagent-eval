<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserSearchController extends Controller
{
    public function search(Request $request)
    {
        $name = $request->input('name');
        $rows = DB::select("SELECT * FROM users WHERE name = ?", [$name]);

        return response()->json($rows);
    }
}
