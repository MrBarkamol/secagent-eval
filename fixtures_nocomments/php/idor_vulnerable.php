<?php

namespace App\Http\Controllers;

use App\Models\Invoice;
use Illuminate\Http\Request;

class InvoiceController extends Controller
{
    public function show(Request $request, $id)
    {
        $invoice = Invoice::findOrFail($id);

        return response()->json($invoice);
    }
}
