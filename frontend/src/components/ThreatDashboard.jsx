/**
 * ThreatDashboard - Real-time threat intelligence and incident overview
 * Advanced SOC analyst dashboard with interactive visualizations
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Grid, Card, CardContent, Typography, Box, Chip, Alert,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Paper, LinearProgress, IconButton, Tooltip, Badge, Divider,
  Dialog, DialogTitle, DialogContent, DialogActions, Button,
  List, ListItem, ListItemText, ListItemIcon, Tabs, Tab
} from '@mui/material';
import {
  Security, Warning, Error, CheckCircle, Visibility,
  NetworkCheck, BugReport, Shield, Timeline, Assessment,
  Notifications, PlayArrow, Pause, Stop, Refresh
} from '@mui/icons-material';
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend,
  ResponsiveContainer, ScatterChart, Scatter
} from 'recharts';
import { format, subHours, subDays } from 'date-fns';

// Color schemes for different threat levels
const SEVERITY_COLORS = {
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#fbc02d',
  low: '#388e3c'
};

const THREAT_TYPE_COLORS = {
  malware: '#e91e63',
  network_intrusion: '#9c27b0',
  data_exfiltration: '#3f51b5',
  behavioral_anomaly: '#00bcd4',
  suspicious_activity: '#ff9800'
};

const ThreatDashboard = () => {
  // State management
  const [threats, setThreats] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [stats, setStats] = useState({});
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [activeTab, setActiveTab] = useState(0);
  const [realTimeEnabled, setRealTimeEnabled] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // WebSocket connection for real-time updates
  const [ws, setWs] = useState(null);

  // Initialize WebSocket connection
  useEffect(() => {
    if (realTimeEnabled) {
      const websocket = new WebSocket('ws://localhost:8000/ws/threats');
      
      websocket.onopen = () => {
        console.log('WebSocket connected');
        setError(null);
      };
      
      websocket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        setThreats(prev => [...data.latest_threats, ...prev].slice(0, 100));
        setStats(data.stats);
      };
      
      websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
        setError('Real-time connection failed');
      };
      
      websocket.onclose = () => {
        console.log('WebSocket disconnected');
      };
      
      setWs(websocket);
      
      return () => {
        websocket.close();
      };
    }
  }, [realTimeEnabled]);

  // Fetch initial data
  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      
      // Fetch threats, incidents, and stats
      const [threatsRes, incidentsRes, statsRes] = await Promise.all([
        fetch('/api/v1/threats/recent'),
        fetch('/api/v1/incidents?limit=20'),
        fetch('/api/v1/threats/stats')
      ]);
      
      const threatsData = await threatsRes.json();
      const incidentsData = await incidentsRes.json();
      const statsData = await statsRes.json();
      
      setThreats(threatsData.threats || []);
      setIncidents(incidentsData.incidents || []);
      setStats(statsData.stats || {});
      
    } catch (err) {
      setError('Failed to fetch dashboard data');
      console.error('Dashboard data fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  // Generate mock data for charts (in production, this would come from API)
  const generateThreatTrendData = () => {
    const data = [];
    for (let i = 23; i >= 0; i--) {
      const time = subHours(new Date(), i);
      data.push({
        time: format(time, 'HH:mm'),
        threats: Math.floor(Math.random() * 20) + 5,
        incidents: Math.floor(Math.random() * 8) + 1,
        blocked: Math.floor(Math.random() * 15) + 10
      });
    }
    return data;
  };

  const generateSeverityDistribution = () => [
    { name: 'Critical', value: stats.critical || 5, color: SEVERITY_COLORS.critical },
    { name: 'High', value: stats.high || 15, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: stats.medium || 35, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: stats.low || 45, color: SEVERITY_COLORS.low }
  ];

  const generateThreatTypeData = () => [
    { name: 'Malware', value: 25, color: THREAT_TYPE_COLORS.malware },
    { name: 'Network Intrusion', value: 20, color: THREAT_TYPE_COLORS.network_intrusion },
    { name: 'Data Exfiltration', value: 15, color: THREAT_TYPE_COLORS.data_exfiltration },
    { name: 'Behavioral Anomaly', value: 25, color: THREAT_TYPE_COLORS.behavioral_anomaly },
    { name: 'Suspicious Activity', value: 15, color: THREAT_TYPE_COLORS.suspicious_activity }
  ];

  // Event handlers
  const handleIncidentClick = (incident) => {
    setSelectedIncident(incident);
  };

  const handleCloseIncidentDialog = () => {
    setSelectedIncident(null);
  };

  const toggleRealTime = () => {
    setRealTimeEnabled(!realTimeEnabled);
  };

  const handleRefresh = () => {
    fetchDashboardData();
  };

  // Render severity chip
  const renderSeverityChip = (severity) => (
    <Chip
      label={severity.toUpperCase()}
      size="small"
      sx={{
        backgroundColor: SEVERITY_COLORS[severity],
        color: 'white',
        fontWeight: 'bold'
      }}
    />
  );

  // Render threat type chip
  const renderThreatTypeChip = (threatType) => (
    <Chip
      label={threatType.replace('_', ' ').toUpperCase()}
      size="small"
      variant="outlined"
      sx={{
        borderColor: THREAT_TYPE_COLORS[threatType],
        color: THREAT_TYPE_COLORS[threatType]
      }}
    />
  );

  if (loading) {
    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <LinearProgress />
        <Typography variant="h6" sx={{ mt: 2, textAlign: 'center' }}>
          Loading Threat Intelligence Dashboard...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ display: 'flex', alignItems: 'center' }}>
          <Shield sx={{ mr: 2, color: 'primary.main' }} />
          ThreatHunter-SOAR Dashboard
        </Typography>
        
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title={realTimeEnabled ? 'Disable Real-time' : 'Enable Real-time'}>
            <IconButton onClick={toggleRealTime} color={realTimeEnabled ? 'success' : 'default'}>
              {realTimeEnabled ? <Pause /> : <PlayArrow />}
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Refresh Data">
            <IconButton onClick={handleRefresh}>
              <Refresh />
            </IconButton>
          </Tooltip>
          
          <Badge badgeContent={threats.length} color="error" max={99}>
            <IconButton>
              <Notifications />
            </IconButton>
          </Badge>
        </Box>
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Key Metrics Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <Security sx={{ fontSize: 40, color: 'primary.main', mr: 2 }} />
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Active Threats
                  </Typography>
                  <Typography variant="h4">
                    {stats.active_threats || 0}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <Warning sx={{ fontSize: 40, color: 'warning.main', mr: 2 }} />
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Open Incidents
                  </Typography>
                  <Typography variant="h4">
                    {incidents.filter(i => i.status !== 'closed').length}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <CheckCircle sx={{ fontSize: 40, color: 'success.main', mr: 2 }} />
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Blocked Today
                  </Typography>
                  <Typography variant="h4">
                    {stats.blocked_today || 0}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <Assessment sx={{ fontSize: 40, color: 'info.main', mr: 2 }} />
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Detection Rate
                  </Typography>
                  <Typography variant="h4">
                    {stats.detection_rate || '98.5'}%
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts Row */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Threat Trends */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Threat Activity (24 Hours)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={generateThreatTrendData()}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <RechartsTooltip />
                  <Legend />
                  <Line type="monotone" dataKey="threats" stroke="#f44336" strokeWidth={2} />
                  <Line type="monotone" dataKey="incidents" stroke="#ff9800" strokeWidth={2} />
                  <Line type="monotone" dataKey="blocked" stroke="#4caf50" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Severity Distribution */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Threat Severity Distribution
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={generateSeverityDistribution()}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {generateSeverityDistribution().map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs for detailed views */}
      <Card>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)}>
            <Tab label="Recent Threats" />
            <Tab label="Active Incidents" />
            <Tab label="Threat Intelligence" />
            <Tab label="System Health" />
          </Tabs>
        </Box>

        {/* Recent Threats Tab */}
        {activeTab === 0 && (
          <CardContent>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Timestamp</TableCell>
                    <TableCell>Threat Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Source</TableCell>
                    <TableCell>Indicators</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {threats.slice(0, 10).map((threat, index) => (
                    <TableRow key={index}>
                      <TableCell>
                        {format(new Date(threat.timestamp || Date.now()), 'HH:mm:ss')}
                      </TableCell>
                      <TableCell>
                        {renderThreatTypeChip(threat.threat_type || 'unknown')}
                      </TableCell>
                      <TableCell>
                        {renderSeverityChip(threat.severity || 'low')}
                      </TableCell>
                      <TableCell>{threat.source || 'Unknown'}</TableCell>
                      <TableCell>
                        <Tooltip title={threat.indicators?.join(', ') || 'No indicators'}>
                          <Chip
                            label={`${threat.indicators?.length || 0} IOCs`}
                            size="small"
                            variant="outlined"
                          />
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <IconButton size="small">
                          <Visibility />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        )}

        {/* Active Incidents Tab */}
        {activeTab === 1 && (
          <CardContent>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Incident ID</TableCell>
                    <TableCell>Title</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Assigned To</TableCell>
                    <TableCell>Created</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {incidents.map((incident) => (
                    <TableRow key={incident.incident_id}>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {incident.incident_id?.substring(0, 8)}...
                        </Typography>
                      </TableCell>
                      <TableCell>{incident.title}</TableCell>
                      <TableCell>
                        {renderSeverityChip(incident.severity)}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={incident.status?.toUpperCase()}
                          size="small"
                          color={incident.status === 'closed' ? 'success' : 'primary'}
                        />
                      </TableCell>
                      <TableCell>{incident.assigned_to || 'Unassigned'}</TableCell>
                      <TableCell>
                        {format(new Date(incident.created_at), 'MMM dd, HH:mm')}
                      </TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => handleIncidentClick(incident)}
                        >
                          <Visibility />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        )}

        {/* Threat Intelligence Tab */}
        {activeTab === 2 && (
          <CardContent>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Threat Type Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={generateThreatTypeData()}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <RechartsTooltip />
                    <Bar dataKey="value" fill="#8884d8">
                      {generateThreatTypeData().map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </Grid>
              
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Intelligence Feeds Status
                </Typography>
                <List>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircle sx={{ color: 'success.main' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary="VirusTotal"
                      secondary="Last updated: 2 minutes ago"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircle sx={{ color: 'success.main' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary="AbuseIPDB"
                      secondary="Last updated: 5 minutes ago"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <Warning sx={{ color: 'warning.main' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary="MISP Feed"
                      secondary="Last updated: 15 minutes ago"
                    />
                  </ListItem>
                </List>
              </Grid>
            </Grid>
          </CardContent>
        )}

        {/* System Health Tab */}
        {activeTab === 3 && (
          <CardContent>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  System Components
                </Typography>
                <List>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircle sx={{ color: 'success.main' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary="Threat Detection Engine"
                      secondary="Operational - Processing 1.2K events/min"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircle sx={{ color: 'success.main' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary="Incident Manager"
                      secondary="Operational - 3 active playbooks"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircle sx={{ color: 'success.main' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary="ML Detector"
                      secondary="Operational - Model accuracy: 94.2%"
                    />
                  </ListItem>
                </List>
              </Grid>
              
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Performance Metrics
                </Typography>
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2">CPU Usage</Typography>
                  <LinearProgress variant="determinate" value={65} />
                  <Typography variant="caption">65%</Typography>
                </Box>
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2">Memory Usage</Typography>
                  <LinearProgress variant="determinate" value={42} />
                  <Typography variant="caption">42%</Typography>
                </Box>
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2">Disk Usage</Typography>
                  <LinearProgress variant="determinate" value={78} />
                  <Typography variant="caption">78%</Typography>
                </Box>
              </Grid>
            </Grid>
          </CardContent>
        )}
      </Card>

      {/* Incident Detail Dialog */}
      <Dialog
        open={!!selectedIncident}
        onClose={handleCloseIncidentDialog}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Incident Details: {selectedIncident?.title}
        </DialogTitle>
        <DialogContent>
          {selectedIncident && (
            <Box>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Severity</Typography>
                  {renderSeverityChip(selectedIncident.severity)}
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Status</Typography>
                  <Chip label={selectedIncident.status?.toUpperCase()} />
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2">Description</Typography>
                  <Typography variant="body2">
                    {selectedIncident.description}
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2">MITRE Techniques</Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    {selectedIncident.mitre_techniques?.map((technique) => (
                      <Chip key={technique} label={technique} size="small" />
                    ))}
                  </Box>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseIncidentDialog}>Close</Button>
          <Button variant="contained">View Full Details</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ThreatDashboard;