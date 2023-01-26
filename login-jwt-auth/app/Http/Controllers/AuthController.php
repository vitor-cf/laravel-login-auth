<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{
    /* construct => classe para que possamos usar o middleware dentro dela para bloquear o acesso
     não autenticado a determinados métodos dentro do AuthControlle:api */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register']]);
    }

    /* Login => método que autentica email e senha, quando o usuario é autenticado com sucesso
    retorna o token deste usuario JWT. O token gerado é recuparado e retornado com JSON */
    public function login(Request $request)
    {
        // valida se foi passado email e senha e respectivos tipos de dados
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
        $credentials = $request->only('email', 'password'); // Recupera um subconjunto de dados de entrada
        //Utilizando Auth::attempt pegando como parâmetros as credenciais referenciadas acima ele aceita
        //array de pares com chave e valor se nao encontrar o email e a password na tabela de colunas do banco
        // retorna uma mensagem de 'Unauthorized'
        $token = Auth::attempt($credentials); // attempt => utilizado para lidar com tentativas de usuarios
        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized',
            ], 401);
        }

        $user = Auth::user(); // verifica credenciais do usuario
        // retorna em formato json caso o usuario seja autorizado
        return response()->json([
                'status' => 'success',
                'user' => $user,
                'authorisation' => [
                    'token' => $token, // token JWT
                    'type' => 'bearer', // tipo da autentificação
                ]
            ]);

    }

    public function register(Request $request){
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);
        // utilizando a model User e acessando o metodo create para enviar dados novos para o banco
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password), // Hash=> salvar a senha
        ]);

        // recebe os dados enviados pelo usuario e retorna em formato json junto com o token
        $token = Auth::login($user);
        return response()->json([
            'status' => 'success',
            'message' => 'User created successfully',
            'user' => $user,
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }

    public function logout()
    {
        Auth::logout();
        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out',
        ]);
    }

    public function refresh()
    {
        return response()->json([
            'status' => 'success',
            'user' => Auth::user(),
            'authorisation' => [
                'token' => Auth::refresh(),
                'type' => 'bearer',
            ]
        ]);
    }

    public function show($id) {
        return User::findOrFail($id)->all();
    }

}
