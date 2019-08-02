## Composer Commands

* Show all commands:
    php artisan

* Create Laravel Project:
    composer create-project --prefer-dist laravel/laravel projectName

* View it On Local Development Server:
    php artisan serve
    This command will start a development server at http://localhost:8000

* Application Key:
    php artisan key:generate


## Laravel Routes

* View all registered routes:
    php artisan route:list

* Laravel handles routes in Routes/web.php files

    Available Router Methods

    Route::get($uri, $callback);
    Route::post($uri, $callback);
    Route::put($uri, $callback);
    Route::patch($uri, $callback);
    Route::delete($uri, $callback);
    Route::options($uri, $callback);

* You may need to register a route that responds to multiple HTTP verbs.
    Route::match(['get', 'post'], '/', function () {
        return "Hello";
    });

* You may even register a route that responds to all HTTP verbs .
    Route::any('/', function () {
        return "Hello";
    });

    Route::get('/', function () {
        return 'Hello World';
    });

    Route::get('/user', 'UserController@index');

* Route to return View only (or with data)
    Route::view('/url', 'dir.viewName');
    Route::view('/url', 'viewName', ['name' => 'Taylor'])

* Route Parameters:
    Route::get('posts/{post}/comments/{comment}', function ($postId, $commentId) {
        return "Post ID: ".$postId." Comment ID: ".$commentId;
    });

* Optional Parameters:
    Route::get('user/{name?}', function ($name = 'John') {
        return $name;
    });

* Regular Expression Constraints:
    Route::get('user/{id}/{name}', function ($id, $name) {
        //you can you one or more args
    })->where(['id' => '[0-9]+', 'name' => '[a-z]+']);

* Named Routes / Redirect routes:
    Route::get('user/{id}/profile', function ($id) {
        //params
    })->name('profile');

    How to use it:
    // Generating URLs...
    $url = route('profile', ['id' => 1]);

    // Generating Redirects...
    return redirect()->route('profile', ['id' => 1]);

* Check / Get Current Route in middleware:
    $request->route()->named('profile');

* Group routes shares same middlewares:
    Route::middleware(['first', 'second'])->group(function () {
        Route::get('/', function () {
            // Uses first & second Middleware
        });

        Route::get('user/profile', function () {
            // Uses first & second Middleware
        });
    });

* Sub-Domain Routing: 
    Route::domain('{account}.myapp.com')->group(function () {
        Route::get('user/{id}', function ($account, $id) {
            //
        });
    });

* Route Prefixes (using name or without name):
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
    Route::get('api/users/{user}', function (App\User $user) {
        return $user->email;
    });

* If you are defining a route that redirects to another URI.
    Route::redirect('/here', '/there');

* Fallback Routes *(When no other route matches the incoming request.):
    //The fallback route should always be the last route registered by your application.
    Route::fallback(function () {
        //Show 404 page
    });

* Rate Limiting: *(Limit route requests per minute)
    //Access the following group of routes 60 times per minute.

    Route::middleware('auth:api', 'throttle:60,1')->group(function () {
        Route::get('/user', function () {
            //
        });
    });

* Accessing The Current Route:
    $route = Route::current();
    $name = Route::currentRouteName();
    $action = Route::currentRouteAction();



## Laravel Middlewares

* filter HTTP requests entering your application.

* Defining Middleware:
    php artisan make:middleware CheckAge

* In handle() function of middleware define rules.

* Registering Middlewares:
  - Global Middleware:
    List the middleware class in the $middleware property of your app/Http/Kernel.php class.

  - Assigning Middleware To Routes:
    First assign the middleware a key in your app/Http/Kernel.php file.
    To add your middleware append it to this list $routeMiddleware and assign it a key of your choosing.
    After that use it IN ROUTES:
    
    Route::get('admin/profile', function () {
        //
    })->middleware('myMiddleware');  

* Assign multiple middlewares to the route:
    Route::get('/', function () {
        //
    })->middleware('first', 'second');

* Middleware Groups:
    Sometimes you may want to group several middleware under a single key to make them 
    easier to assign to routes. You may do this using the $middlewareGroups property of your HTTP kernel.
    
    Route::group(['middleware' => ['web']], function () {
        //
    });

* Sorting Middleware
    Rarely, you may need your middleware to execute in a specific order. In this case, you may 
    specify your middleware priority using the $middlewarePriority property of your app/Http/Kernel.php file.

* Middleware Parameters
    Middleware can also receive additional parameters. For example, if your application needs to verify that the authenticated user has a given "role" before performing a given action, you could create a CheckRole middleware that receives a role name as an additional argument.

    Additional middleware parameters will be passed to the middleware after the $next argument:

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
        
    Middleware parameters may be specified when defining the route by separating the middleware name and parameters with a :. Multiple parameters should be delimited by commas:
    Route::put('post/{id}', function ($id) {
        //
    })->middleware('role:editor'); 


## Laravel CSRF protection (Cross-Site Request Forgery)

* To disable it just comment this middleware in 'web' middlewares group.
    OR
* You may also exclude the routes by adding their URIs to the $except 
  property of the VerifyCsrfToken middleware.
        protected $except = [
            'stripe/*',
            'http://example.com/foo/bar',
            'http://example.com/foo/*',
        ];

* Jusy add @csrf after every <form> tag

* CSRF Protection for HTML forms:
    - Any HTML forms pointing to POST, PUT, or DELETE routes that are defined 
    in the web routes file should include a CSRF token field. Otherwise, 
    the request will be rejected.
    add @csrf just after <form> tag

    - HTML forms do not support PUT, PATCH or DELETE actions. So, when defining 
      PUT, PATCH or  DELETE. add @method('PUT') just after <form> tag

* For ajax requests:
    - add meta tag in headers <meta name="csrf-token" content="{{ csrf_token() }}">
    - instruct ajax Setup
        $.ajaxSetup({
            headers: {
                'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
            }
        });


## Laravel Controllers

* Defining Controllers:
    - Simple Controller: 
        php artisan make:controller ShowProfile

    - Single Request Controller: (One method handle every request in controller)
        php artisan make:controller ShowProfile --invokable

    - Resource controller:
        php artisan make:controller ShowProfile --resource

    - Controller bind with Modal:
        php artisan make:controller PhotoController --resource --model=Photo

    - API Controller
        php artisan make:controller API/PhotoController --api

* Single Action Controllers:
    Create: php artisan make:controller ShowProfile --invokable

* Controller Middleware:
    - Route Method:
        Route::get('profile', 'UserController@show')->middleware('auth');
    
    - Using Controller method
        public function __construct(){
            $this->middleware('auth');  //Apply to all requests
            $this->middleware('log')->only('index');    //Apply to only index method request
            $this->middleware('subscribed')->except('store');   //Apply to all except store method request
        }   

* Resource Controller:
    php artisan make:controller ShowProfile --resource
     - Than
    Route::resource('photos', 'PhotoController');

    - Register many resource controllers at once:
        Route::resources([
            'photos' => 'PhotoController',
            'posts' => 'PostController'
        ]);

* API Resource Routes:
    Route::apiResources([
        'photos' => 'PhotoController',
        'posts' => 'PostController'
    ]);

* Adding methods to the controller:
    Route::get('photos/popular', 'PhotoController@method');

* Laravel Constructor:
    class UserController extends Controller{
        /* The user repository instance. */
        protected $users;
        public function __construct(UserRepository $users)
        {
            $this->users = $users;
        }
    }

* Laravel Request:
    use Illuminate\Http\Request;

* To generate a route cache: *after when add new route regenerate cache
    php artisan route:cache

* Clear Route Cache:
    php artisan route:clear


## Laravel Request

* Access it by: use Illuminate\Http\Request;

* Retrieving The Request Path:
    $uri = $request->path();
    http://domain.com/foo/bar -> return 'foo/bar'

* Matching url pattern 
    if($request->is('admin/*'))

* Retrieving The Request URL:
    // Without Query String...
    $url = $request->url();
    // With Query String...
    $url = $request->fullUrl();

* Retrieving The Request Method:
    if ($request->isMethod('post'))

* Retrieving All Input Data:
    $input = $request->all();

* Retrieving An Input Value:
    $name = $request->input('name');
    OR if not present return default
    $name = $request->input('name', 'malik ateeq');
    $name = $request->input('products.0.name'); // Use dots to access the arrays

* Retrieving A Portion Of The Input Data:
    $input = $request->only(['username', 'password']);
    $input = $request->except(['credit_card']);

* Determining If An Input Value Is Present:
    if ($request->has('name')) //present
    if ($request->filled('name')) //present and not empty

* Retrieving Cookies From Requests: *If you try to change cookies it will consider as invalid
    $value = $request->cookie('name');

* Attaching Cookies To Responses:
    return response('Hello World')->cookie(
        'name', 'value', $minutes
    );

* Retrieving Uploaded Files:
    if ($request->hasFile('photo'))
    $file = $request->file('photo');
    $file = $request->photo;

* File Paths & Extensions:
    $path = $request->photo->path();
    $extension = $request->photo->extension();

* Storing Uploaded Files:
    $path = $request->photo->store('images');
    $path = $request->photo->store('images', 's3');
    $path = $request->photo->storeAs('images', 'filename.jpg');

## HTTP Responses Return responses
* Responses:
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

    - Redirecting To External Domains
    return redirect()->away('https://www.google.com');

    return response()->file($pathToFile);

* View Responses:
    return response()
            ->view('hello', $data, 200);
    
* JSON Responses:
    return response()->json([
        'name' => 'Abigail',
        'state' => 'CA'
    ]);

## Laravel Views

* Determining If A View Exists:
    if (View::exists('emails.customer'))

* Passing Data To Views:
    return view('greetings', ['name' => 'Victoria']);
    return view('greeting')->with('name', 'Victoria');

* Sharing Data With All Views:
    Goto AppServiceProvider>boot() method
        public function boot(){
            View::share('key', 'value');
        }

## Laravel Validation

* add this in the start of the method where validation is required
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
    'author.description' => 'required',

* Errors will be available in $errors 

* Display errors in View
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
    make a file "fileName.blade.php" in "resources/views"

* Template Layout:
    - Master page:
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
        <!-- /resources/views/alert.blade.php -->
        <div class="alert alert-danger">
            {{ $slot }}
        </div>

        *The {{ $slot }} variable will contain the content we wish to inject into the component.

    - Use the component:
        @component('alert')
            <strong>Whoops!</strong> Something went wrong!
        @endcomponent

    - Inject content into slot:
        <!-- /resources/views/alert.blade.php -->
        <div class="alert alert-danger">
            <div class="alert-title">{{ $title }}</div>
            {{ $slot }}
        </div>

        Inject it as:
        @component('alert')
            @slot('title')
                Forbidden
            @endslot
            You are not allowed to access this resource!
        @endcomponent

    - Access components in a subdirectories:
        if present in: "resources/views/components/alert.blade.php"
        then access as: "components.alert"

    - Define conponents in boot() method of "App/Providers/AppServiceProvider.php"
        Define:
            use Illuminate\Support\Facades\Blade;
            Blade::component('components.alert', 'alert');
        Use:
            @alert
                You are not allowed to access this resource!
            @endalert

* Displaying Data in Views:
    You may display the contents of the name variable like so:
        Hello, {{ $name }}.

    - Displaying Unescaped Data:
    If you do not want your data to be escaped, you may use the following syntax:
        Hello, {!! $name !!}.

    - Rendering JSON:
        <script>
            var app = <?php echo json_encode($array); ?>;
        </script>
        
        OR Use blade directive @json

        <script>
            var app = @json($array);
            var app = @json($array, JSON_PRETTY_PRINT);
        </script>

    - Displaying JS Variables:
        1. 
            Hello, @{{ jsVariable }}
        2. 
        @verbatim
            <div class="container">
                Hello, {{ jsVariable }}
            </div>
        @endverbatim

* If Statements:
    @if (count($records) === 1)
        I have one record!
    @elseif (count($records) > 1)
        I have multiple records!
    @else
        I don't have any records!
    @endif

* Unless directive:
    @unless (Auth::check())
        You are not signed in.
    @endunless

* isset and empty directives:
    @isset($records)
        // $records is defined and is not null...
    @endisset

    @empty($records)
        // $records is "empty"...
    @endempty

* Authentication Directives:

    @auth
        // The user is authenticated...
    @endauth

    @guest
        // The user is not authenticated...
    @endguest

* Authentication guards:

    @auth('admin')
        // The user is authenticated...
    @endauth

    @guest('admin')
        // The user is not authenticated...
    @endguest

* Has Section Directives:

    @hasSection('navigation')
        <div class="pull-right">
            @yield('navigation')
        </div>

        <div class="clearfix"></div>
    @endif

* Switch Statements:

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

    - Break and Continue:
        @foreach ($users as $user)
            @if ($user->type == 1)
                @continue
            @endif

            <li>{{ $user->name }}</li>

            @if ($user->number == 5)
                @break
            @endif
        @endforeach

    - The Loop Variable:
        @foreach ($users as $user)
            @if ($loop->first)
                This is the first iteration.
            @endif
            @if ($loop->last)
                This is the last iteration.
            @endif
            <p>This is user {{ $user->id }}</p>
        @endforeach

    - The Loop Variable For Nested Loops:
        @foreach ($users as $user)
            @foreach ($user->posts as $post)
                @if ($loop->parent->first)
                    This is first iteration of the parent loop.
                @endif
            @endforeach
        @endforeach

    - Some other loop variable properties:
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
    {{-- This comment will not be present in the rendered HTML --}}

* PHP Directive to use some kind of php code:
    @php
        // php code...
    @endphp

* CSRF Field: 
    @csrf   //Just below the <form> tag

* Method Field: *Only for PUT, PATCH, or DELETE spoofing
    @method('PUT')  //Just below the <form> tag

* Validation Errors:
    <input id="title" type="text" class="@error('title') is-invalid @enderror">
    
    @error('title')
        <div class="alert alert-danger">{{ $message }}</div>
    @enderror

* Including Sub-Views:
    <div>
        @include('shared.errors')
        <form>
            <!-- Form Contents -->
        </form>
    </div>

* Custom If Statements (Use env variables in blade)

    Define in boot() methof of "App/Providers/AppServiceProvider"
        use Illuminate\Support\Facades\Blade;
        public function boot(){
            Blade::if('env', function ($environment) {
                return app()->environment($environment);
            });
        }
    Once the custom conditional has been defined, we can easily use it on our templates:
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

* Writing CSS:
    Laravel's package.json file includes the bootstrap package to help you get started 
    prototyping your application's frontend using Bootstrap. However, feel free to add 
    or remove packages from the package.json

    - For compiling CSS:
        i. Before compiling your CSS, install your project's frontend dependencies using the
            Node package manager (NPM): 
                run composer command:   npm install

        ii. After That you can compile your SASS files to plain CSS using Laravel Mix. 
        The "npm run dev" command will process the instructions in your  webpack.mix.js file. 
        Typically, your compiled CSS will be placed in the public/css directory:
            For one time compilation:   npm run dev
            To Watch every change & compile:     nmp run watch
        
        iii. To add another css/js file for compilation:
            add in webpack.mix.js file

            mix.js('resources/js/app.js', 'public/js')
                .js('resources/js/custom.js', 'public/js')
                .sass('resources/sass/app.scss', 'public/css')
                .sass('resources/sass/custom.scss', 'public/css');


* Writing JavaScript:
    All of the JavaScript dependencies required by your application can be found 
    in the  package.json file in the project's root directory. 

* Compiling Assets (Mix):
    - Installing Node:
        Before triggering Mix, you must first ensure that Node.js and NPM are installed on your machine.
            node -v
            npm -v
        Install Laravel Mix:    
            npm install
        
        * "package.json" define Node dependencies while "composer.json" define PHP dependencies.
    
    - Running Mix:
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
                mix.less('resources/less/app.less', 'public/css');
        
        2: Sass:
            The sass method allows you to compile Sass into CSS. You may use the method like so:
                mix.sass('resources/sass/app.scss', 'public/css');

        3: Plain CSS:
            If you would just like to concatenate some plain CSS stylesheets into a single file, 
            you may use the styles method.
                mix.styles([
                    'public/css/vendor/normalize.css',
                    'public/css/vendor/videojs.css'
                ], 'public/css/all.css');

        4: Javascript:
            mix.js('resources/js/app.js', 'public/js');

        5: React:
            Mix can automatically install the Babel plug-ins necessary for React support. 
            To get started, replace your mix.js() call with mix.react():
                    mix.react('resources/js/app.jsx', 'public/js');
        
* Environment Variables:

    You may inject environment variables into Mix by prefixing a key in your .env file with MIX_:
    MIX_SENTRY_DSN_PUBLIC=http://example.com
    After the variable has been defined in your .env file, you may access via the process.env object. 
    If the value changes while you are running a watch task, you will need to restart the task:
    
        process.env.MIX_SENTRY_DSN_PUBLIC

## Laravel Authentication

* Setting things up Just Run: 
    php artisan make:auth
    php artisan migrate

* Authentication Quickstart:
    Laravel ships with several pre-built authentication controllers, which are located 
    in the  App\Http\Controllers\Auth namespace.

    The "RegisterController" handles new user registration, 
    the "LoginController" handles authentication, 
    the "ForgotPasswordController" handles e-mailing links for resetting passwords, 
    and the "ResetPasswordController" contains the logic to reset passwords.

    - Routing:
            ~ php artisan make:auth
        This command should be used on fresh applications and will install a layout 
        view, registration and login views, as well as routes for all authentication 
        end-points. A HomeController will also be generated to handle post-login requests 
        to your application's dashboard.

* To disable registration process:
    If your application doesn’t need registration, you may disable it by removing 
    the newly created RegisterController and modifying your route declaration.
        Auth::routes(['register' => false]);.\

* Retrieving The Authenticated User:
    
    use Illuminate\Support\Facades\Auth;

    // Get the currently authenticated user...
    $user = Auth::user();

    // Get the currently authenticated user's ID...
    $id = Auth::id();
    OR
    $request->user() returns an instance of the authenticated user...

* Determining If The Current User Is Authenticated:
    use Illuminate\Support\Facades\Auth;
    if (Auth::check()) {
        // The user is logged in...
    }

* Redirecting Unauthenticated Users:
    When the auth middleware detects an unauthorized user, it will redirect the user to 
    the login named route. You may modify this behavior by updating the redirectTo 
    function in your  app/Http/Middleware/Authenticate.php file.

* Logging Out:
    Auth::logout();



* Customizations:
    
    - Path Customization:
        When a user is successfully authenticated, they will be redirected to the /home URI. 
        You can customize the post-authentication redirect location by defining a redirectTo 
        property on the  LoginController, RegisterController, ResetPasswordController, 
        and  VerificationController:

            protected $redirectTo = '/';
    
        Next, you should modify the RedirectIfAuthenticated middleware's handle method to use your 
        new URI when redirecting the user.
        If the redirect path needs custom generation logic you may define a redirectTo 
        method instead of a redirectTo property:
        *The redirectTo method will take precedence over the redirectTo attribute.

            protected function redirectTo(){
                return '/path';
            }

    - Username Customization:
            By default, Laravel uses the email field for authentication. If you would like to customize this, 
            you may define a username method on your LoginController:

                public function username()
                {
                    return 'username';
                }


* Customizations for Multiple Users Auth:
    1: Add extra fileds in Users migrations if any like '$table->string('role');'
    2: Add fileds in User model $fillable array like 'role'
    3: Add input fields in "Resources/Views/Auth/register.balde.php" like select field for 'role'
    4: Also add those fields in validator() & create() methods of "Controllers/Auth/RegisterController.php"
    
    5: Create Controllers and Views for each role, like StudentController, AdminController, TeacherController etc.
    6: Define dashboard routes for each role. @index() should return dashboard view for every role.
    imp.
    7: Create new Middleware 'checkRole'
        ~ php artisan make:middleware checkRole

        - middleware file setup:
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
                    else    // If not matched goto login then there'll be redirected to correct path
                    {
                        return redirect('login');
                    }
                    // return $next($request);
                }
            }
        
        8: Apply middleware to every role Controller like below in AdminController:
            public function __construct()
            {
                //Specify required role for this controller here in checkRole:xyz
                $this->middleware(['auth', 'checkRole:admin']); 
            }
        
        9: Everything is setup now control redirects towards /home by:

            i. Goto App/Http/Middleware/RedirectIfAuthenticated.php file and change handle() function:
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

            ii. Goto LoginController and add redirectTo() method

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
            
            10: Goto LoginController, RegisterController, ResetPasswordController and VerificationController
                
                Change this 
                    protected $redirectTo = '/home';
                to this
                    protected $redirectTo = '/login';
            
        EVERYTHING IS DONE!!! 
 

## Laravel

## Laravel