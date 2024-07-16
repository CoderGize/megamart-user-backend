<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Mail\SendOTP;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:8|confirmed',
                'location' => 'nullable|string|max:255',
                'phone_number' => 'nullable|string|max:20',
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors(), 422);
            }

            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'location' => $request->location,
                'phone' => $request->phone_number,
                'verified' => 0,
            ]);


            $token = mt_rand(1000, 9999);
            $user->otp = $token;
            $user->save();

            $data = [
                "pin" => $token,
            ];
            Mail::to($user->email)->send(new SendOTP($data));

            return response()->json([
                'message' => 'OTP sent to email ' . $user->email,
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], 500);
        }
    }


    public function login(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|string|email',
                'password' => 'required|string',
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors(), 422);
            }

            $user = User::where('email', $request->email)->first();

            if (!$user || !Hash::check($request->password, $user->password)) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Invalid email or password.',
                ], 401);
            }

            if (!$user->verified) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Email is not verified.',
                ], 403);
            }

            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'user' => $user,
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], 500);
        }
    }


    public function verifyOtp(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|string|email|max:255',
                'otp' => 'required|integer',
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors(), 422);
            }

            $user = User::where('email', $request->email)->where('otp', $request->otp)->first();

            if (!$user) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Invalid OTP or email.',
                ], 400);
            }

            $user->verified = true;
            $user->otp = null;
            $user->save();

            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'message' => 'Email verified successfully.',
                'access_token' => $token,
                'token_type' => 'Bearer',
                'user' => $user,
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], 500);
        }
    }


    public function forgotPassword(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|string|email|max:255',
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors(), 422);
            }

            $user = User::where('email', $request->email)->first();

            if (!$user) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Email does not exist.',
                ], 404);
            }

            $token = mt_rand(1000, 9999);
            $user->otp = $token;
            $user->save();

            $data = [
                "pin" => $token,
            ];
            Mail::to($user->email)->send(new SendOTP($data));

            return response()->json([
                'message' => 'OTP sent to email ' . $user->email,
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], 500);
        }
    }


     // Reset Password
     public function resetPassword(Request $request)
     {
         try {
             $validator = Validator::make($request->all(), [
                 'email' => 'required|string|email|max:255',
                 'otp' => 'required|integer',
                 'password' => 'required|string|min:8|confirmed',
             ]);

             if ($validator->fails()) {
                 return response()->json($validator->errors(), 422);
             }

             $user = User::where('email', $request->email)->where('otp', $request->otp)->first();

             if (!$user) {
                 return response()->json([
                     'status' => 'error',
                     'message' => 'Invalid OTP or email.',
                 ], 400);
             }

             $user->password = Hash::make($request->password);
             $user->otp = null;
             $user->save();

             return response()->json([
                 'message' => 'Password reset successfully.',
             ], 200);

         } catch (\Exception $e) {
             return response()->json([
                 'status' => 'error',
                 'message' => $e->getMessage(),
             ], 500);
         }
     }

     public function changePassword(Request $request)
        {
            try {
                $validator = Validator::make($request->all(), [
                    'current_password' => 'required|string',
                    'new_password' => 'required|string|min:8|confirmed',
                ]);

                if ($validator->fails()) {
                    return response()->json($validator->errors(), 422);
                }

                $user = $request->user();

                if (!Hash::check($request->current_password, $user->password)) {
                    return response()->json([
                        'status' => 'error',
                        'message' => 'Current password is incorrect.',
                    ], 401);
                }

                $user->password = Hash::make($request->new_password);
                $user->save();

                return response()->json([
                    'message' => 'Password changed successfully.',
                ], 200);

            } catch (\Exception $e) {
                return response()->json([
                    'status' => 'error',
                    'message' => $e->getMessage(),
                ], 500);
            }
        }
        public function changeProfile(Request $request)
        {
            try {
                $validator = Validator::make($request->all(), [
                    'name' => 'nullable|string|max:255',
                    'email' => 'nullable|string|email|max:255|unique:users,email,' . $request->user()->id,
                    'location' => 'nullable|string|max:255',
                    'phone_number' => 'nullable|string|max:20',
                ]);

                if ($validator->fails()) {
                    return response()->json($validator->errors(), 422);
                }

                $user = $request->user();

                if ($request->has('name')) {
                    $user->name = $request->name;
                }
                if ($request->has('email')) {
                    $user->email = $request->email;
                }
                if ($request->has('location')) {
                    $user->location = $request->location;
                }
                if ($request->has('phone_number')) {
                    $user->phone = $request->phone_number;
                }

                $user->save();

                return response()->json([
                    'message' => 'Profile updated successfully.',
                    'user' => $user,
                ], 200);

            } catch (\Exception $e) {
                return response()->json([
                    'status' => 'error',
                    'message' => $e->getMessage(),
                ], 500);
            }
        }

}
