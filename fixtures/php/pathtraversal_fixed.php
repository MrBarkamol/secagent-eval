<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class FileDownloadController extends Controller
{
    public function download(Request $request)
    {
        $name = basename($request->input('name'));
        $path = storage_path('app/files/' . $name);

        if (!is_file($path)) {
            abort(404);
        }

        return response()->download($path);
    }
}
