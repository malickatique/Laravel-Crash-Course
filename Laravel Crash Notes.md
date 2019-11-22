## Composer Commands

* Show all commands:
    - php artisan

* Create Laravel Project:
    - composer create-project --prefer-dist laravel/laravel projectName

* View it On Local Development Server:
    - php artisan serve
    - This command will start a development server at http://localhost:8000

* Application Key:
    - php artisan key:generate


## Laravel Routes

* View all registered routes:
    - php artisan route:list

* Laravel handles routes in Routes/web.php files

    ** Available Router Methods

    1. Route::get($uri, $callback);
    2. Route::post($uri, $callback);
    3. Route::put($uri, $callback);
    4. Route::patch($uri, $callback);
    5. Route::delete($uri, $callback);
    6. Route::options($uri, $callback);

* You may need to register a route that responds to multiple HTTP verbs.
    ```php
    Route::match(['get', 'post'], '/', functi`on () {
        return "Hello";
    });
    ```
* You may even register a route that responds to all HTTP verbs .
    ```php
    Route::any('/', function () {
        return "Hello";
    });

    Route::get('/', function () {
        return 'Hello World';
    });

    Route::get('/user', 'UserController@index');
    
    ```

* Route to return View only (or with data)
    ```php
    Route::view('/url', 'dir.viewName');
    Route::view('/url', 'viewName', ['name' => 'Taylor'])
    ```
* Route Parameters:
    ```php
    Route::get('posts/{post}/comments/{comment}', function ($postId, $commentId) {
        return "Post ID: ".$postId." Comment ID: ".$commentId;
    });
    ```
* Optional Parameters:
    ```php
    Route::get('user/{name?}', function ($name = 'John') {
        return $name;
    });

* Regular Expression Constraints:
    ```php
    Route::get('user/{id}/{name}', function ($id, $name) {
        //you can you one or more args
    })->where(['id' => '[0-9]+', 'name' => '[a-z]+']);

* Named Routes / Redirect routes:
    ```php
    Route::get('user/{id}/profile', function ($id) {
        //params
    })->name('profile');

    // How to use it
    // Generating URLs...
    $url = route('profile', ['id' => 1]);

    // Generating Redirects...
    return redirect()->route('profile', ['id' => 1]);

* Check / Get Current Route in middleware:
    ```php
    $request->route()->named('profile');

* Group routes shares same middlewares:
    ```php
    Route::middleware(['first', 'second'])->group(function () {
        Route::get('/', function () {
            // Uses first & second Middleware
        });

        Route::get('user/profile', function () {
            // Uses first & second Middleware
        });
    });

* Sub-Domain Routing:
    ```php 
    Route::domain('{account}.myapp.com')->group(function () {
        Route::get('user/{id}', function ($account, $id) {
            //
        });
    });

* Route Prefixes (using name or without name):
    ```php
    Route::prefix('admin')->group(function () {
        Route::get('users', function () {
            // Matches The "/admin/users" URL
        });
    });
    Route::name('admin.')->group(function () {
        Route::get('users', function () {
            // Route assigned name "admin.users"...
        })->name('users');
    });

* Routes API access Models:
    ```php
    Route::get('api/users/{user}', function (User $user) {
        return $user->email;
    });

* If you are defining a route that redirects to another URI.
    ```php
    Route::redirect('/here', '/there');

* Fallback Routes *(When no other route matches the incoming request.):
    ```php
    //The fallback route should always be the last route registered by your application.
    Route::fallback(function () {
        //Show 404 page
    });

* Rate Limiting: *(Limit route requests per minute)
    ```php
    //Access the following group of routes 60 times per minute.
    Route::middleware('auth:api', 'throttle:60,1')->group(function () {
        Route::get('/user', function () {
            //
        });
    });

* Accessing The Current Route:
    ```php
    $route = Route::current();
    $name = Route::currentRouteName();
    $action = Route::currentRouteAction();



## Laravel Middlewares

* Laravel Middlewares filter HTTP requests entering your application.

* Defining Middleware:
    - php artisan make:middleware CheckAge

* In handle() function of middleware define rules.

* Registering Middlewares:
  - Global Middleware: <br>
    List the middleware class in the $middleware property of your app/Http/Kernel.php class.

  - Assigning Middleware To Routes: <br>
    First assign the middleware a key in your app/Http/Kernel.php file.
    To add your middleware append it to this list $routeMiddleware and assign it a key of your choosing.
    After that use it IN ROUTES:
    ```php
    Route::get('admin/profile', function () {
        //
    })->middleware('myMiddleware');  

* Assign multiple middlewares to the route:
    ```php
    Route::get('/', function () {
        //
    })->middleware('first', 'second');

* Middleware Groups: <br>
    Sometimes you may want to group several middleware under a single key to make them 
    easier to assign to routes. You may do this using the $middlewareGroups property of your HTTP kernel.
    ```php
    Route::group(['middleware' => ['web']], function () {
        //
    });

* Sorting Middleware:  <br>
    Rarely, you may need your middleware to execute in a specific order. In this case, you may 
    specify your middleware priority using the $middlewarePriority property of your app/Http/Kernel.php file.

* Middleware Parameters:  <br>
    Middleware can also receive additional parameters. For example, if your application needs to verify that the authenticated user has a given "role" before performing a given action, you could create a CheckRole middleware that receives a role name as an additional argument.

    Additional middleware parameters will be passed to the middleware after the $next argument:
    ```php
    <?php
    namespace App\Http\Middleware;
    use Closure;
    class CheckRole{
        public function handle($request, Closure $next, $role){
            if (! $request->user()->hasRole($role)) {
                // Redirect...
            }
            return $next($request);
        }
    }
        
    //Middleware parameters may be specified when defining the route by separating the middleware 
    //name and parameters with a :Multiple parameters should be delimited by commas.
    
    Route::put('post/{id}', function ($id) {
        //
    })->middleware('role:editor'); 


## Laravel CSRF protection (Cross-Site Request Forgery)

* To disable it just comment this middleware in 'web' middlewares group.
    OR
* You may also exclude the routes by adding their URIs to the $except 
  property of the VerifyCsrfToken middleware:
    ```php
        protected $except = [
            'stripe/*',
            'http://example.com/foo/bar',
            'http://example.com/foo/*',
        ];
    ```

* CSRF Protection for HTML forms: <br>
    - Any HTML forms pointing to POST, PUT, or DELETE routes that are defined 
    in the web routes file should include a CSRF token field. Otherwise, 
    the request will be rejected.
    add @csrf just after <form> tag
    ```php
        @csrf
    ```
    
    - HTML forms do not support PUT, PATCH or DELETE actions. So, when defining 
      PUT, PATCH or  DELETE. add @method('PUT') just after <form> tag
    ```php
        @method('PUT')
        @method('PATCH')
        @method('DELETE') 
    ```
* For ajax requests:
    - Add meta tag in headers 
        ```php
        <meta name="csrf-token" content="{{ csrf_token() }}">
    - Instruct ajax Setup:
        ```javascript
        $.ajaxSetup({
            headers: {
                'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
            }
        });


## Laravel Controllers

* Defining Controllers:
    - Simple Controller:
        ```php 
        - php artisan make:controller ShowProfile

    - Single Request Controller: (One method handle every request in controller)
        ```php
        - php artisan make:controller ShowProfile --invokable

    - Resource controller:
        ```php
        - php artisan make:controller ShowProfile --resource

    - Controller bind with Modal:
        ```php
        - php artisan make:controller PhotoController --resource --model=Photo

    - API Controller
        ```php
        - php artisan make:controller API/PhotoController --api

* Single Action Controllers:
    Create:
    ```php 
    - php artisan make:controller ShowProfile --invokable

* Controller Middleware:
    - Route Method:
        ```php
        Route::get('profile', 'UserController@show')->middleware('auth');
    
    - Using Controller method
        ```php
        public function __construct(){
            $this->middleware('auth');  //Apply to all requests
            $this->middleware('log')->only('index');    //Apply to only index method request
            $this->middleware('subscribed')->except('store');   //Apply to all except store method request
        }   

* Resource Controller:
    - php artisan make:controller ShowProfile --resource
     - Than
    ```php
    Route::resource('photos', 'PhotoController');

    // Register many resource controllers at once.
    Route::resources([
        'photos' => 'PhotoController',
        'posts' => 'PostController'
    ]);

* API Resource Routes.
    ```php
    Route::apiResources([
        'photos' => 'PhotoController',
        'posts' => 'PostController'
    ]);

* Adding methods to the controller.
    ```php
    Route::get('photos/popular', 'PhotoController@method');

* Laravel Constructor:
    ```php
    class UserController extends Controller{
        /* The user repository instance. */
        protected $users;
        public function __construct(UserRepository $users)
        {
            $this->users = $users;
        }
    }

* Laravel Request:
    ```php
    - use Illuminate\Http\Request;

* To generate a route cache: *after when add new route regenerate cache:
    ```php
    - php artisan route:cache

* Clear Route Cache:
    ```php
    - php artisan route:clear


## Laravel Request

* Access it by: 
    ```php
    - use Illuminate\Http\Request;

* Retrieving The Request Path:
    ```php
    $uri = $request->path();
    http://domain.com/foo/bar -> return 'foo/bar'

* Matching url pattern 
    ```php
    if($request->is('admin/*'))

* Retrieving The Request URL:
    ```php
    // Without Query String...
    $url = $request->url();
    // With Query String...
    $url = $request->fullUrl();

* Retrieving The Request Method:
    ```php
    if ($request->isMethod('post'))

* Retrieving All Input Data:
    ```php
    $input = $request->all();

* Retrieving An Input Value:
    ```php
    $name = $request->input('name');
    OR if not present return default
    $name = $request->input('name', 'malik ateeq');
    $name = $request->input('products.0.name'); // Use dots to access the arrays

* Retrieving A Portion Of The Input Data:
    ```php
    $input = $request->only(['username', 'password']);
    $input = $request->except(['credit_card']);

* Determining If An Input Value Is Present:
    ```php
    if ($request->has('name')) //present
    if ($request->filled('name')) //present and not empty

* Retrieving Cookies From Requests: *If you try to change cookies it will consider as invalid
    ```php
    $value = $request->cookie('name');

* Attaching Cookies To Responses:
    ```php
    return response('Hello World')->cookie(
        'name', 'value', $minutes
    );

* Retrieving Uploaded Files:
    ```php
    if ($request->hasFile('photo'))
    $file = $request->file('photo');
    $file = $request->photo;

* File Paths & Extensions:
    ```php
    $path = $request->photo->path();
    $extension = $request->photo->extension();

* Storing Uploaded Files:
    ```php
    $path = $request->photo->store('images');
    $path = $request->photo->store('images', 's3');
    $path = $request->photo->storeAs('images', 'filename.jpg');

## HTTP Responses Return responses
* Responses:
    ```php
    Route::get('/', function () {
        return 'Hello World';
    });

    Route::get('/', function () {
        return [1, 2, 3];
    });

    Route::get('home', function () {
        return response('Hello World', 200)
                    ->header('Content-Type', 'text/plain');
    });

* Redirects:
    - Redirect from controller:
    ```php
    return redirect('home')

    Route::get('dashboard', function () {
        return redirect('home/dashboard');
    });

    Route::post('user/profile', function () {
        // Validate the request...
        return back()->withInput();
    });

    return redirect()->route('login');

    return redirect()->route('profile', [$user]);

    return redirect()->action('HomeController@index');

    return redirect()->action(
        'UserController@profile', ['id' => 1]
    );

    // Redirecting To External Domains
    return redirect()->away('https://www.google.com');

    return response()->file($pathToFile);

* View Responses:
    ```php
    return response()
            ->view('hello', $data, 200);
    
* JSON Responses:
    ```javascript
    return response()->json([
        'name' => 'Abigail',
        'state' => 'CA'
    ]);

## Laravel Views

* Determining If A View Exists:
    ```php
    if (View::exists('emails.customer'))

* Passing Data To Views:
    ```php
    return view('greetings', ['name' => 'Victoria']);
    return view('greeting')->with('name', 'Victoria');

* Sharing Data With All Views:
    ```php
    Goto AppServiceProvider>boot() method
        public function boot(){
            View::share('key', 'value');
        }

## Laravel Validation

* add this in the start of the method where validation is required
    ```php
    $validatedData = $request->validate([
        'title' => 'required|unique:posts|max:255',
        'body' => 'required',
    ]);

    // When failed terminate exec.
    $request->validate([
        'title' => 'bail|required|unique:posts|max:255',
        'body' => 'required',
    ]);

* For nested attributes:
    ```php
    'author.description' => 'required',

* Errors will be available in $errors 

* Display errors in View
    ```php
    @if ($errors->any())
        <div class="alert alert-danger">
            <ul>
                @foreach ($errors->all() as $error)
                    <li>{{ $error }}</li>
                @endforeach
            </ul>
        </div>
    @endif



## Laravel Blade Templates

* Define a blade file:
    - make a file "fileName.blade.php" in "resources/views"

* Template Layout:
    - Master page:
        ```php
        <html>
        <head>
            <title>Parent - @yield('title')</title>
        </head>
        <body>
            @section('sidebar')
                This is the master sidebar.
            @show   <!-- Show child content of section "sidebar" here -->

            <div class="container">
                @yield('content')   <!-- Place child content for section "content" -->
            </div>
        </body>
        </html>

    - Extending A Layout:
        ```php
        @extends('layouts.app')
        @section('title', 'Child Page')
        @section('sidebar')
            @parent     <!-- Place parent content of section "sidebar" here -->
            <p>This is appended to the master sidebar.</p>
        @endsection
        @section('content')
            <p>This is my body content.</p>
        @endsection

* Components & Slots (Resuable throughout the project)

    - Make a component:
        ```php
        <!-- /resources/views/alert.blade.php -->
        <div class="alert alert-danger">
            {{ $slot }}
        </div>

        *The {{ $slot }} variable will contain the content we wish to inject into the component.

    - Use the component:
        ```php
        @component('alert')
            <strong>Whoops!</strong> Something went wrong!
        @endcomponent

    - Inject content into slot:
        ```php
        <!-- /resources/views/alert.blade.php -->
        <div class="alert alert-danger">
            <div class="alert-title">{{ $title }}</div>
            {{ $slot }}
        </div>

        // Inject it as
        @component('alert')
            @slot('title')
                Forbidden
            @endslot
            You are not allowed to access this resource!
        @endcomponent

    - Access components in a subdirectories:
        ```php
        if present in: "resources/views/components/alert.blade.php"
        then access as: "components.alert"

    - Define conponents in boot() method of "App/Providers/AppServiceProvider.php"
        1. Define:
            ```php
            use Illuminate\Support\Facades\Blade;
            Blade::component('components.alert', 'alert');
        2. Use:
            ```php
            @alert
                You are not allowed to access this resource!
            @endalert

* Displaying Data in Views:
    - You may display the contents of the name variable like so:
        ```php
        Hello, {{ $name }}.

    - Displaying Unescaped Data:
        ```php
        // If you do not want your data to be escaped, you may use the following syntax:
        Hello, {!! $name !!}.

    - Rendering JSON:
        ```php
        <script>
            var app = <?php echo json_encode($array); ?>;
        </script>
        
        // OR Use blade directive @json

        <script>
            var app = @json($array);
            var app = @json($array, JSON_PRETTY_PRINT);
        </script>

    - Displaying JS Variables:
        ```php
        //1. 
            Hello, @{{ jsVariable }}
        //2. 
        @verbatim
            <div class="container">
                Hello, {{ jsVariable }}
            </div>
        @endverbatim

* If Statements:
    ```php
    @if (count($records) === 1)
        I have one record!
    @elseif (count($records) > 1)
        I have multiple records!
    @else
        I don't have any records!
    @endif

* Unless directive:
    ```php
    @unless (Auth::check())
        You are not signed in.
    @endunless

* isset and empty directives:
    ```php
    @isset($records)
        // $records is defined and is not null...
    @endisset

    @empty($records)
        // $records is "empty"...
    @endempty

* Authentication Directives:
    ```php
    @auth
        // The user is authenticated...
    @endauth

    @guest
        // The user is not authenticated...
    @endguest

* Authentication guards:
    ```php
    @auth('admin')
        // The user is authenticated...
    @endauth

    @guest('admin')
        // The user is not authenticated...
    @endguest

* Has Section Directives:
    ```php
    @hasSection('navigation')
        <div class="pull-right">
            @yield('navigation')
        </div>

        <div class="clearfix"></div>
    @endif

* Switch Statements:
    ```php
    @switch($i)
        @case(1)
            First case...
            @break

        @case(2)
            Second case...
            @break

        @default
            Default case...
    @endswitch

* Loops:
    ```php
    @for ($i = 0; $i < 10; $i++)
        The current value is {{ $i }}
    @endfor

    @foreach ($users as $user)
        <p>This is user {{ $user->id }}</p>
    @endforeach

    @forelse ($users as $user)
        <li>{{ $user->name }}</li>
        @empty
        <p>No users</p>
    @endforelse

    @while (true)
        <p>I'm looping forever.</p>
    @endwhile
    ```
* Break and Continue
    ```php
    @foreach ($users as $user)
        @if ($user->type == 1)
            @continue
        @endif

        <li>{{ $user->name }}</li>

        @if ($user->number == 5)
            @break
        @endif
    @endforeach

* The Loop Variable:
    ```php
    @foreach ($users as $user)
        @if ($loop->first)
            This is the first iteration.
        @endif
        @if ($loop->last)
            This is the last iteration.
        @endif
        <p>This is user {{ $user->id }}</p>
    @endforeach

* The Loop Variable For Nested Loops:
    ```php
    @foreach ($users as $user)
        @foreach ($user->posts as $post)
            @if ($loop->parent->first)
                This is first iteration of the parent loop.
            @endif
        @endforeach
    @endforeach

* Some other loop variable properties:  <br>
    Property    ,	Description
    $loop->index    ,	The index of the current loop iteration (starts at 0).
    $loop->iteration    ,	The current loop iteration (starts at 1).
    $loop->remaining    ,	The iterations remaining in the loop.
    $loop->count    ,	The total number of items in the array being iterated.
    $loop->first    ,	Whether this is the first iteration through the loop.
    $loop->last ,	Whether this is the last iteration through the loop.
    $loop->even ,	Whether this is an even iteration through the loop.
    $loop->odd  ,	Whether this is an odd iteration through the loop.
    $loop->depth    ,	The nesting level of the current loop.
    $loop->parent   ,	When in a nested loop, the parent's loop variable.

* Comments:
    ```php
    {{-- This comment will not be present in the rendered HTML --}}

* PHP Directive to use some kind of php code:
    ```php
    @php
        // php code...
    @endphp

* CSRF Field: 
    ```php
    @csrf   //Just below the <form> tag

* Method Field: *Only for PUT, PATCH, or DELETE spoofing
    ```php
    @method('PUT')  //Just below the <form> tag

* Validation Errors:
    ```php
    <input id="title" type="text" class="@error('title') is-invalid @enderror">
    
    @error('title')
        <div class="alert alert-danger">{{ $message }}</div>
    @enderror

* Including Sub-Views:
    ```php
    <div>
        @include('shared.errors')
        <form>
            <!-- Form Contents -->
        </form>
    </div>

* Custom If Statements (Use env variables in blade)

    - Define in boot() methof of "App/Providers/AppServiceProvider"
        ```php
        use Illuminate\Support\Facades\Blade;
        public function boot(){
            Blade::if('env', function ($environment) {
                return app()->environment($environment);
            });
        }
    - Once the custom conditional has been defined, we can easily use it on our templates:
        ```php
        @env('local')
            // The application is in the local environment...
        @elseenv('testing')
            // The application is in the testing environment...
        @else
            // The application is not in the local or testing environment...
        @endenv


## Laravel Localization, Other Language support

    https://laravel.com/docs/5.8/localization

## Laravel JavaScript & CSS Scaffolding

* Writing CSS: <br>
    Laravel's package.json file includes the bootstrap package to help you get started 
    prototyping your application's frontend using Bootstrap. However, feel free to add 
    or remove packages from the package.json

    - For compiling CSS: <br>
        1. Before compiling your CSS, install your project's frontend dependencies using the
            Node package manager (NPM): 
                - run composer command:  
            ```php
            - npm install

        1. After That you can compile your SASS files to plain CSS using Laravel Mix. 
        The "npm run dev" command will process the instructions in your  webpack.mix.js file. 
        Typically, your compiled CSS will be placed in the public/css directory:
        ```php
            //For one time compilation:   
            npm run dev
            //To Watch every change & compile:     
            nmp run watch
        ```
        1. To add another css/js file for compilation:
            add in webpack.mix.js file
            ```php
            mix.js('resources/js/app.js', 'public/js')
                .js('resources/js/custom.js', 'public/js')
                .sass('resources/sass/app.scss', 'public/css')
                .sass('resources/sass/custom.scss', 'public/css');


* Writing JavaScript: <br>
    All of the JavaScript dependencies required by your application can be found 
    in the  package.json file in the project's root directory. 

* Compiling Assets (Mix):
    - Installing Node:
        Before triggering Mix, you must first ensure that Node.js and NPM are installed on your machine.
    ```php
        - node -v
        - npm -v
        //Install Laravel Mix:      
        - npm install
    ```
        * "package.json" define Node dependencies while "composer.json" define PHP dependencies.
    
    - Running Mix:
        ```php
        // Run all Mix tasks...
        npm run dev

        // Run all Mix tasks and minify output...
        npm run production

        // Watching Assets For Changes
        npm run watch

    - Working With Stylesheets/Scripts:
        1: Less:
            The less method may be used to compile Less into CSS. Let's compile our primary app.less 
            file to public/css/app.css.
    ```php
    mix.less('resources/less/app.less', 'public/css');
    ``` 
        2: Sass:
            The sass method allows you to compile Sass into CSS. You may use the method like so:
    ```php
    mix.sass('resources/sass/app.scss', 'public/css');
    ```
        3: Plain CSS:
            If you would just like to concatenate some plain CSS stylesheets into a single file, 
            you may use the styles method.
    ```php
    mix.styles([
        'public/css/vendor/normalize.css',
        'public/css/vendor/videojs.css'
    ], 'public/css/all.css');
    ```
        4: Javascript:
    ```php
    mix.js('resources/js/app.js', 'public/js');
    ```
        5: React:
            Mix can automatically install the Babel plug-ins necessary for React support. 
            To get started, replace your mix.js() call with mix.react():
    ```php
    mix.react('resources/js/app.jsx', 'public/js');
    ```
* Environment Variables: <br>

    You may inject environment variables into Mix by prefixing a key in your .env file with MIX_:
    MIX_SENTRY_DSN_PUBLIC=http://example.com
    After the variable has been defined in your .env file, you may access via the process.env object. 
    If the value changes while you are running a watch task, you will need to restart the task:
    
        - process.env.MIX_SENTRY_DSN_PUBLIC

## Laravel Authentication

* Setting things up Just Run: 
    ```php
    - php artisan make:auth
    - php artisan migrate

* Authentication Quickstart: <br>
    Laravel ships with several pre-built authentication controllers, which are located 
    in the  App\Http\Controllers\Auth namespace.

    The "RegisterController" handles new user registration, 
    the "LoginController" handles authentication, 
    the "ForgotPasswordController" handles e-mailing links for resetting passwords, 
    and the "ResetPasswordController" contains the logic to reset passwords.

* Routing:
    ```php
    - php artisan make:auth
    ```
    This command should be used on fresh applications and will install a layout 
    view, registration and login views, as well as routes for all authentication 
    end-points. A HomeController will also be generated to handle post-login requests 
    to your application's dashboard.

* To disable registration process: <br>
    If your application doesn’t need registration, you may disable it by removing 
    the newly created RegisterController and modifying your route declaration.
    ```php
    Auth::routes(['register' => false]);

* Retrieving The Authenticated User:
    ```php
    use Illuminate\Support\Facades\Auth;

    // Get the currently authenticated user...
    $user = Auth::user();

    // Get the currently authenticated user's ID...
    $id = Auth::id();
    OR
    $request->user() //returns an instance of the authenticated user...

* Determining If The Current User Is Authenticated:
    ```php
    use Illuminate\Support\Facades\Auth;
    if (Auth::check()) {
        // The user is logged in...
    }

* Redirecting Unauthenticated Users: <br>
    When the auth middleware detects an unauthorized user, it will redirect the user to 
    the login named route. You may modify this behavior by updating the redirectTo 
    function in your  app/Http/Middleware/Authenticate.php file.

* Logging Out:
    ```php
    Auth::logout();

    
* Path Customization: <br>
    When a user is successfully authenticated, they will be redirected to the /home URI. 
    You can customize the post-authentication redirect location by defining a redirectTo 
    property on the  LoginController, RegisterController, ResetPasswordController, 
    and  VerificationController:
    ```php
    protected $redirectTo = '/';
    
* Next, you should modify the RedirectIfAuthenticated middleware's handle method to use your 
    new URI when redirecting the user.
    If the redirect path needs custom generation logic you may define a redirectTo 
    method instead of a redirectTo property. The redirectTo method will take precedence over the redirectTo attribute.
    ```php
    protected function redirectTo(){
        return '/path';
    }
    ```
* Username Customization: <br>
    By default, Laravel uses the email field for authentication. If you would like to customize this, 
    you may define a username method on your LoginController:
    ```php
    public function username()
    {
        return 'username';
    }


## Customizations for Multiple Users Auth:

1. Add extra fileds in Users migrations if any like 
    ```php
    $table->string('role');
    
2. Add fileds in User model $fillable array like 'role'
3. Add input fields in "Resources/Views/Auth/register.balde.php" like select field for 'role'
4. Also add those fields in validator() & create() methods of "Controllers/Auth/RegisterController.php"
    
5. Create Controllers and Views for each role, like StudentController, AdminController, TeacherController etc.
6. Define dashboard routes for each role. @index() should return dashboard view for every role.
    
7. Create new Middleware 'checkRole'
    ```php
    - php artisan make:middleware checkRole
    ```

    * 'checkRole' Middleware file changess:
    ```php
        <?php
        namespace App\Http\Middleware;
        use Illuminate\Support\Facades\Auth;    //Add Auth facades
        use Closure;
        class checkRole
        {
            public function handle($request, Closure $next, $role)  // ***Add 3rd parameter $role
            {
                if (!Auth::check()) //Optional
                    return redirect('login');

                $user = Auth::user();
                if($user->role == $role)    // this $role coming from Controller to verify role authority
                {
                    return $next($request);
                }
                else    // If not matched goto login then there will be redirected to correct path
                {
                    return redirect('login');
                }
                // return $next($request);
            }
        }
        ?>
    ```
        
8. Apply middleware to every role Controller like below in AdminController:
    ```php
    public function __construct()
    {
        //Specify required role for this controller here in checkRole:xyz
        $this->middleware(['auth', 'checkRole:admin']); 
    }
    
9. Everything is setup now control redirects towards /home by:

    1. Goto App/Http/Middleware/RedirectIfAuthenticated.php file and change handle() function:
        ```php
        //Specify redirects as many roles you have
        public function handle($request, Closure $next, $guard = null)
        {
            if (Auth::guard($guard)->check()) 
            {
                if(Auth::user()->role == 'admin')
                {
                    return redirect('/admin');
                }
                else if(Auth::user()->role == 'teacher')
                {
                    return redirect('/teacher');
                }
                else if(Auth::user()->role == 'student')
                {
                    return redirect('/student');
                }
                // return redirect('/home');
            }
            return $next($request);
        }

    1. Goto LoginController and add redirectTo() method
        ```php
        protected function redirectTo()
        {
            if(Auth::user()->role == 'admin')
            {
                return '/admin';
            }
            else if(Auth::user()->role == 'teacher')
            {
                return '/teacher';
            }
            else if(Auth::user()->role == 'student')
            {
                return '/student';
            }
        }
        
10. Goto LoginController, RegisterController, ResetPasswordController and VerificationController
            
    ```php
    //Change this
    protected $redirectTo = '/home';
    //to this
    protected $redirectTo = '/login';
    ```

    EVERYTHING IS DONE!!! 
 

## Laravel Account Email Varification

* Model Preparation <br>
    To get started, verify that your App\User model implements
    ```php
    class User extends Authenticatable implements MustVerifyEmail
    {
        use Notifiable;
        // ...
    }

* The Email Verification Column: <br>
    Next, your user table must contain an email_verified_at column to store the date 
    and time that the email address was verified. By default, the users table migration 
    included with the Laravel framework already includes this column.

* Routing: <br>
    In Routes/web.php file add
    ```php
    Auth::routes(['verify' => true]);

* Protecting Routes: <br>
    Route middleware can be used to only allow verified users to access a given route. Laravel ships with a verified middleware, which is defined at  Illuminate\Auth\Middleware\EnsureEmailIsVerified. Since this middleware is already registered in your application's HTTP kernel, all you need to do is attach the middleware to a route definition:
    
    ```php
    Route::get('profile', function () {
        // Only verified users may enter...
    })->middleware('verified');

## Laravel Eloquent

* Each database table has a corresponding "Model" which is used to interact with that table.
* Models allow you to query for data in your tables, as well as insert new records into the table.

* Defining Models:
    ```php
    // Create Model Only
    php artisan make:model Flight

    // Create Model along with Migration
    php artisan make:model Flight --migration
    //or
    php artisan make:model Flight -m

* Set Table Names of a Model: <br>
    By convention, the "snake case", plural name of the class will be used as the table name unless 
    another name is explicitly specified. So, in this case, Eloquent will assume the "Flight" model 
    stores records in the "flights" table.

    ```php
    // Specify table name
    protected $table = 'my_flights';

    // For Mass Assignment
    protected $fillable = ['name', 'phone', 'email'];
    
    // The attributes that aren't mass assignable.
    protected $guarded = ['price'];

* Primary Keys: <br>
    Eloquent will also assume that each table has a primary key column named id. You may define a 
    protected $primaryKey property to override this convention:

    ```php

    // Specify table primary key
    protected $primaryKey = 'flight_id';

    // If key is not auto increment then add
    public $incrementing = false;

    // If key is not integer than
    protected $keyType = 'string';

    // If you don't want to handle timestamps
    public $timestamps = false;

    // Default Attribute Values
    <?php
    namespace App;
    use Illuminate\Database\Eloquent\Model;
    class Flight extends Model{
        /**
        * The model's default values for attributes.
        * @var array
        */
        protected $attributes = [
            'delayed' => false,
        ];
    }

* Retrieving Models: <br>

    ```php
    // Fetch all data
    <?php
    use App\Flight;
    $flights = Flight::all();
    foreach ($flights as $flight) {
        echo $flight->name;
    }

    // Fetch with conditions
    $flights = Flight::where('active', 1)
            ->orderBy('name', 'desc')
            ->take(10)
            ->get();

    // Fresh record
    $flight = Flight::where('number', 'FR 900')->first();
    $flight->number = 'FR 456';
    $flight->refresh();
    $flight->number; // "FR 900"

    // Get Chunk results
    Flight::chunk(200, function ($flights) {
        foreach ($flights as $flight) {
            //
        }
    });

    // Retrieve a model by its primary key...
    $flight = Flight::find(1);

    // Retrieve the first model matching the query constraints...
    $flight = Flight::where('active', 1)->first();

    // Will return array of results
    $flights = Flight::find([1, 2, 3]);

    // If not found exception will be thrown
    $model = Flight::findOrFail(1);
    $model = Flight::where('legs', '>', 100)->firstOrFail();

    // Retrieving Aggregates
    $count = Flight::where('active', 1)->count();
    $max = Flight::where('active', 1)->max('price');

* Inserting, Updating & Deleting Models: <br>

    - Insert Data: <br>
        ```php
        // Validate the request...
        $flight = new Flight;
        $flight->name = $request->name;
        $flight->save();

        // Create and Store a record 
        $flight = App\Flight::create(['name' => 'Flight 10']);

    - Updates Records: <br>
    
        ```php
        // Validate the request...
        $flight = Flight::find(1);
        $flight->name = 'New Flight Name';
        $flight->save();

        // Mass Updates
        App\Flight::where('active', 1)
                ->where('destination', 'San Diego')
                ->update(['delayed' => 1]);
        
        // Fill data
        $flight->fill(['name' => 'Flight 22']);
        ```

    - Deletes Records: <br>
        ```php
        // Find and delete
        $flight = Flight::find(1);
        $flight->delete();

        //Delete by PK
        Flight::destroy(1);
        Flight::destroy(1, 2, 3);
        Flight::destroy([1, 2, 3]);
        Flight::destroy(collect([1, 2, 3]));

        // Delete where sth
        $deletedRows = Flight::where('active', 0)->delete();

        // Soft Deleting: When models are soft deleted, they are not actually removed from your database. 
        use Illuminate\Database\Eloquent\SoftDeletes;
        class Flight extends Model
        {
            use SoftDeletes;
            Schema::table('flights', function (Blueprint $table) {
                $table->softDeletes();
            });
        }

        // Querying Soft Deleted Models
        $flights = App\Flight::withTrashed()
                        ->where('account_id', 1)
                        ->get();

        // Restoring Soft Deleted Models
        $flight->restore();
        // and 
        App\Flight::withTrashed()
                ->where('airline_id', 1)
                ->restore();
                
        // Force deleting a single model instance...
        $flight->forceDelete();

        // Force deleting all related models...
        $flight->history()->forceDelete();

* For Query Scopes, Comparing Models, Events and Observers goto: <br>
    https://laravel.com/docs/5.8/eloquent#query-scopes

* Relationships: <br> 


## Eloquent: Relationships

Eloquent relationships are defined as methods on your Eloquent model classes.

* One To One Relationship: <br>
    A one-to-one relationship is a very basic relation. For example, a User model might be associated with one Phone. To define this relationship, we place a phone method on the User model. The phone method should call the hasOne method and return its result.

    ```php
    <?php
    namespace App;
    use Illuminate\Database\Eloquent\Model;
    class User extends Model
    {
        public function phone()
        {
            return $this->hasOne('App\Phone');
        }
        // The first argument passed to the hasOne method is the name of the related model.
        // Once the relationship is defined, we may retrieve the related record using Eloquent's dynamic properties. 
    }
    ```

    ```php
    $phone = User::find(1)->phone;
    ```

#### Eloquent determines the foreign key of the relationship based on the model name. In this case, the Phone model is automatically assumed to have a user_id foreign key. If you wish to override this convention, you may pass a second argument to the hasOne method. Foreign key in Phone table of User.

    ```php
    return $this->hasOne('App\Phone', 'foreign_key');

    return $this->hasOne('App\Phone', 'foreign_key', 'local_key');
    ```

#### 'foreign_key' == Exact name of foreign key (id of User Table) in Phone table.
#### 'local_key' == Exact name of primary key (of User) in User table. <br>

### Defining The Inverse Of The Relationship: <br>
   * So, we can access the Phone model from our User. Now, let's define a relationship on the  Phone model that will let us access the User that owns the phone. We can define the inverse of a hasOne relationship using the belongsTo method:
    
    ```php
    <?php
    namespace App;
    use Illuminate\Database\Eloquent\Model;
    class Phone extends Model{
        /**
         * Get the user that owns the phone.
         */
        public function user(){
            return $this->belongsTo('App\User');
            //OR
            return $this->belongsTo('App\User', 'foreign_key_in_Phone', 'PK_in_User');
        }
    }
    `

* One To Many Relationship:
    A one-to-many relationship is used to define relationships where a single model owns any amount of other models. For example, a blog post may have an infinite number of comments. 
    
    ```php
    return $this->hasMany('App\Comment', 'foreign_key', 'local_key');
    
    // Chaining conditions
    $comment = App\Post::find(1)->comments()->where('title', 'foo')->first();

### One To Many (Inverse):

* Allow a comment to access its parent post.
    
    ```php
    <?php

    namespace App;

    use Illuminate\Database\Eloquent\Model;

    class Comment extends Model
    {
        /**
        * Get the post that owns the comment.
        */
        public function post()
        {
            return $this->belongsTo('App\Post');
            // OR
            return $this->belongsTo('App\Post', 'foreign_key', 'other_key');
        }
    }

    // Retriving data:
    $comment = App\Comment::find(1);
    echo $comment->post->title;

* Many To Many Relationship:
    Many-to-many relations are slightly more complicated than hasOne and hasMany relationships. An example of such a relationship is a user with many roles, where the roles are also shared by other users. For example, many users may have the role of "Admin". To define this relationship, three database tables are needed: users, roles, and role_user. The  role_user table is derived from the alphabetical order of the related model names, and contains the user_id and role_id columns.

    Many-to-many relationships are defined by writing a method that returns the result of the  belongsToMany method. For example, let's define the roles method on our User model:
    
    ```php
    <?php

    namespace App;

    use Illuminate\Database\Eloquent\Model;

    class User extends Model
    {
        /**
        * The roles that belong to the user.
        */
        public function roles()
        {
            return $this->belongsToMany('App\Role');
            // OR
            return $this->belongsToMany('App\Role', 'role_user', 'user_id', 'role_id');
        }
    }



## Laravel Extras:

* Deploy Project to Shared Hosting:

1. Remove unnecessery space/comments from start of Routes > web.php file
2. Add '/*' in $except, file in middlewares folder verifyCsrfToken.php if tokenMismatchException occurs.
3. If public and root folders are present seperately then: 

    ```php
	In \App\Providers\AppServiceProvider register() method.
	$this->app->bind('path.public', function() {
        	return '/home4/demoaspi/public_html/2019/ovrvue/';});
    ```

4. change paths in index.php file

5. For database configurations:
    ```php
	DB_USERNAME=demoaspi_defuser
	DB_PASSWORD=~CUkh$0Y9QLK
    ```

6. Other ISSUE while deploying:

1. Axios request Base URL:
   Change axios request base url: In Resources>Assets>js>boostrap.js
   Add this: window.axios.defaults.baseURL = '/2019/ovrvue';
   after this:  window.axios = require('axios');

1. Pics and other path issues:
    ```php
    // For Vue Js
    add Vue.prototype.$baseURL = '/2019/ovrvue/'; in resources>assets>js>app.js file
    then change all path with Vue.prototype.$baseURL+/images etc
    ```

1. Uncomment following
    ```php
    //Uncomment it for live server in bootstrap.js
    // authEndpoint: 'http://www.demoaspire.com/2019/ovrvue/broadcasting/auth',
    
    Vue.prototype.$baseURL = '/2019/ovrvue'; = '/2019/ovrvue'; in resources>assets>js>app.js
    window.axios.defaults.baseURL = '/2019/ovrvue'; in resources>assets>js>bootstrap.js

    // window.axios.defaults.headers.common['X-CSRF-TOKEN'] = token.content; //Uncomment it if needed


##Other Issues
1. When mex length 191 deb_fields
    ```php
    //go to app/Providers/AppServiceProvider.php
    //place this in boot function plus include
    use Illuminate\Support\Facades\Schema;
    Schema::defaultStringLength(191);
    ```
