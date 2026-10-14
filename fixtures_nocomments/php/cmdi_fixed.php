<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class DiagnosticsController extends Controller
{
    public function ping(Request $request)
    {
        $host = $request->input('host');
        $output = shell_exec("ping -c 1 " . escapeshellarg($host));

        return response($output);
    }
}
