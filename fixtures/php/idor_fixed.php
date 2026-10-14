<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class InvoiceController extends Controller
{
    public function show(Request $request, $id)
    {
        // Query is scoped to the current user's invoices, so a foreign id 404s.
        $invoice = $request->user()->invoices()->findOrFail($id);

        return response()->json($invoice);
    }
}
