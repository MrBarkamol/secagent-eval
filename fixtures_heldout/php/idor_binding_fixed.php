<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\Request;

class OrderNoteController extends Controller
{
    public function update(Request $request, Order $order)
    {
        $this->authorize('update', $order);
        $data = $request->validate(['note' => 'nullable|string|max:500']);
        $order->update($data);

        return response()->json($order);
    }
}
