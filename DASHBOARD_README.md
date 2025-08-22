# WAF Dashboard

A comprehensive, real-time dashboard for monitoring and managing your Web Application Firewall (WAF) system.

## 🚀 Features

### 📊 Real-time Monitoring
- **Live Statistics**: View total requests, blocked/allowed requests, and block rate
- **Real-time Updates**: WebSocket-powered live updates every 5 seconds
- **Attack Visualization**: Interactive charts showing attack types and patterns
- **Recent Activity Feed**: Live feed of recent requests with status indicators

### ⚙️ Configuration Management
- **Rate Limiting Settings**: Configure max requests, time windows, and block durations
- **ML Model Management**: Switch between different ML model versions
- **Plugin Control**: Enable/disable individual WAF plugins
- **Confidence Thresholds**: Adjust ML model sensitivity

### 🛡️ Security Controls
- **IP Management**: Block/unblock IP addresses with custom durations
- **Rule Management**: Add, edit, and delete WAF rules through the UI
- **Real-time Blocking**: Immediate IP blocking from the dashboard

### 📈 Analytics & Reporting
- **Daily Trends**: Visualize request patterns over time
- **Attack Analysis**: Detailed breakdown of attack types
- **Performance Metrics**: Block rates and system performance

### 🔍 Request Logging
- **Detailed Logs**: Complete request history with filtering
- **Pagination**: Navigate through large datasets efficiently
- **Search & Filter**: Filter by blocked/allowed requests
- **Request Details**: View full request information

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- MongoDB running on localhost:27017
- Required Python packages (see requirements.txt)

### Setup

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Start MongoDB** (if not already running):
   ```bash
   # On Windows
   mongod
   
   # On Linux/Mac
   sudo systemctl start mongod
   ```

3. **Run the WAF System**:
   ```bash
   # Option 1: Run both WAF and Dashboard together
   python run_waf.py
   
   # Option 2: Run separately
   # Terminal 1 - WAF Proxy
   cd waf
   python app.py
   
   # Terminal 2 - Dashboard
   cd waf
   python dashboard.py
   ```

## 🌐 Access

- **Dashboard**: http://localhost:5001
- **WAF Proxy**: http://localhost:5000

## 📋 Dashboard Sections

### 1. Dashboard (Main View)
- **Statistics Cards**: Key metrics at a glance
- **Attack Types Chart**: Visual breakdown of blocked requests
- **Recent Activity**: Live feed of recent requests
- **Real-time Updates**: Auto-refreshing data

### 2. Requests
- **Request Log**: Complete history of all requests
- **Filtering**: Show only blocked or all requests
- **Pagination**: Navigate through large datasets
- **Request Details**: View individual request information

### 3. Settings
- **Rate Limiting**: Configure request limits and time windows
- **ML Model**: Select model version and adjust confidence
- **Plugins**: Enable/disable WAF plugins
- **Real-time Saving**: Changes applied immediately

### 4. Rules
- **Rule Editor**: Add, edit, and delete WAF rules
- **Pattern Management**: Configure regex patterns
- **Action Types**: Set rules to block or log
- **Live Updates**: Rules applied immediately

### 5. Blocked IPs
- **IP Management**: View all currently blocked IPs
- **Manual Blocking**: Block IPs with custom duration
- **Unblocking**: Remove IPs from block list
- **Duration Tracking**: See when IPs will be unblocked

### 6. Analytics
- **Trend Analysis**: Daily request patterns
- **Performance Metrics**: System performance over time
- **Summary Statistics**: Key performance indicators

## 🔧 Configuration

### Rate Limiting
- **Max Requests**: Maximum requests per time window
- **Window (seconds)**: Time window for rate limiting
- **Block Time**: Duration to block IPs that exceed limits

### ML Model
- **Model Version**: Select active ML model
- **Confidence Threshold**: Minimum confidence for blocking
- **Enable/Disable**: Toggle ML-based detection

### Plugins
- **Block Admin**: Block access to admin paths
- **Block IP**: IP-based blocking functionality
- **Block User Agent**: User agent-based blocking

## 📊 API Endpoints

The dashboard provides RESTful APIs for integration:

- `GET /api/stats` - Get real-time statistics
- `GET /api/requests` - Get paginated request logs
- `GET /api/settings` - Get current settings
- `POST /api/settings` - Update settings
- `GET /api/blocked-ips` - Get blocked IPs
- `POST /api/block-ip` - Block an IP
- `POST /api/unblock-ip/<ip>` - Unblock an IP
- `GET /api/rules` - Get WAF rules
- `POST /api/rules` - Update WAF rules
- `GET /api/ml-models` - Get available ML models
- `POST /api/set-model/<version>` - Set ML model
- `GET /api/analytics` - Get analytics data

## 🔌 WebSocket Events

Real-time updates via WebSocket:

- `stats_update` - Real-time statistics updates
- `connect` - Connection established
- `disconnect` - Connection lost

## 🎨 Customization

### Styling
- Modify `static/css/dashboard.css` for custom styling
- Update color variables in CSS for theme changes
- Responsive design for mobile devices

### Functionality
- Extend `dashboard.py` for additional API endpoints
- Modify `static/js/dashboard.js` for custom JavaScript
- Add new dashboard sections in `templates/dashboard.html`

## 🐛 Troubleshooting

### Common Issues

1. **MongoDB Connection Error**:
   - Ensure MongoDB is running on localhost:27017
   - Check MongoDB service status

2. **Port Already in Use**:
   - Change ports in `app.py` and `dashboard.py`
   - Kill processes using the ports

3. **Missing Dependencies**:
   - Run `pip install -r requirements.txt`
   - Check Python version compatibility

4. **Dashboard Not Loading**:
   - Check browser console for JavaScript errors
   - Verify static files are being served
   - Check WebSocket connection

### Debug Mode

Run with debug enabled:
```bash
# WAF with debug
cd waf
python app.py

# Dashboard with debug
cd waf
python dashboard.py
```

## 🔒 Security Considerations

- **Access Control**: Consider adding authentication to the dashboard
- **HTTPS**: Use HTTPS in production environments
- **IP Whitelisting**: Restrict dashboard access to specific IPs
- **Log Rotation**: Implement log rotation for MongoDB collections

## 📈 Performance

- **Real-time Updates**: WebSocket for live data
- **Pagination**: Efficient handling of large datasets
- **Caching**: Consider Redis for caching frequently accessed data
- **Database Optimization**: Index MongoDB collections for better performance

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs for error messages
3. Create an issue with detailed information

---

**Happy WAF Management! 🛡️** 