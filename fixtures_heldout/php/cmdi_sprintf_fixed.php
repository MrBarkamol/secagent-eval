<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ThumbnailController extends Controller
{
    public function make(Request $request)
    {
        $file = $request->input('file');
        exec(sprintf('convert %s -resize 200x200 thumb.png', escapeshellarg($file)), $out, $code);

        return response()->json(['ok' => $code === 0]);
    }
}
