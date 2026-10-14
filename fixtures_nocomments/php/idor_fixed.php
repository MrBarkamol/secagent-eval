<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class InvoiceController extends Controller
{
    public function show(Request $request, $id)
    {
        $invoice = $request->user()->invoices()->findOrFail($id);

        return response()->json($invoice);
    }
}
