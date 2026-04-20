<!DOCTYPE html>
<html>
<head>
    <title>OWASP ML Detector</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>

<div class="layout">

    <aside class="sidebar">
        <div class="logo">OWASP ML</div>

        <nav>
            <a href="/" class="nav-item">Dashboard</a>
            <a href="/reports" class="nav-item">Reports</a>
            <a href="/insights" class="nav-item">ML Insights</a>
            <a href="/settings" class="nav-item">Settings</a>
        </nav>

        <div class="sidebar-footer">
            <button id="darkToggle">🌙 Dark Mode</button>
        </div>
    </aside>

    <div class="main">

        <header class="topbar">
            <div>
                <input type="text" placeholder="Search..." class="search-box">
                <button id="refreshBtn">🔄 Refresh</button>
            </div>
            <div>
                <span id="clock"></span>
                <span class="profile">Admin</span>
            </div>
        </header>

        <div class="content">
            {% block content %}{% endblock %}
        </div>

    </div>
</div>

<script src="{{ url_for('static', filename='js/script.js') }}"></script>
</body>
</html>
