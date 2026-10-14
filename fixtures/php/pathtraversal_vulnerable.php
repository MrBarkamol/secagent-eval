<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class FileDownloadController extends Controller
{
    public function download(Request $request)
    {
        $name = $request->input('name');
        $path = storage_path('app/files/' . $name);

        return response()->download($path);
    }
}
