@extends('layouts.master')

@section('title', 'Child Page')

@section('sidebar')
    @parent     <!-- Place parent content of section "sidebar" here -->
    <p>This is appended to the master sidebar.</p>
@endsection

@section('content')
    <p>This is my body content.</p>
@endsection
