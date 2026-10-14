<?php

namespace App\Http\Controllers;

use App\Models\Invoice;
use Illuminate\Http\Request;

class InvoiceController extends Controller
{
    public function show(Request $request, $id)
    {
        // Any authenticated user can read any invoice by guessing the id.
        $invoice = Invoice::findOrFail($id);

        return response()->json($invoice);
    }
}
