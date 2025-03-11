class AdminPortal {
    constructor() {
        this.token = localStorage.getItem('token');
        if (!this.token) {
            window.location.href = '../../auth/login.html';
            return;
        }
        this.initialize();
    }

    async initialize() {
        try {
            // Fetch admin profile
            const response = await fetch('/api/admin/profile', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) {
                throw new Error('Not authorized as admin');
            }

            const data = await response.json();
            if (!data.success || data.user.role !== 'admin') {
                throw new Error('Not authorized as admin');
            }

            this.admin = data.user;
            this.updateUI();
            await this.loadPageData();
        } catch (error) {
            console.error('Error initializing admin portal:', error);
            localStorage.removeItem('token');
            window.location.href = '../../auth/login.html';
        }
    }

    updateUI() {
        // Update admin name
        const adminNameElement = document.getElementById('adminName');
        if (adminNameElement) {
            adminNameElement.textContent = this.admin.name;
        }

        // Update active nav item
        const currentPage = window.location.pathname.split('/').pop();
        document.querySelectorAll('.admin-nav-item').forEach(item => {
            if (item.getAttribute('href') === currentPage) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });
    }

    async loadPageData() {
        const currentPage = window.location.pathname.split('/').pop();
        
        switch (currentPage) {
            case 'dashboard.html':
                await this.loadDashboardData();
                break;
            case 'users.html':
                await this.loadUsersData();
                break;
            case 'properties.html':
                await this.loadPropertiesData();
                break;
            case 'messages.html':
                await this.loadMessagesData();
                break;
        }
    }

    async loadDashboardData() {
        try {
            const response = await fetch('/api/admin/dashboard', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to load dashboard data');
            }

            const data = await response.json();
            if (data.success) {
                this.updateStats(data);
                this.updateRecentActivity(data.recentActivity);
            }
        } catch (error) {
            console.error('Error loading dashboard data:', error);
        }
    }

    updateStats(data) {
        const elements = {
            totalUsers: document.getElementById('totalUsers'),
            totalProperties: document.getElementById('totalProperties'),
            totalDocuments: document.getElementById('totalDocuments')
        };

        Object.entries(elements).forEach(([key, element]) => {
            if (element && data[key] !== undefined) {
                element.textContent = data[key];
            }
        });
    }

    updateRecentActivity(activities = []) {
        const activityList = document.getElementById('recentActivity');
        if (!activityList) return;

        if (!activities.length) {
            activityList.innerHTML = '<p>No recent activity</p>';
            return;
        }

        activityList.innerHTML = activities.map(activity => `
            <div class="activity-item">
                <div class="activity-icon ${activity.type}">
                    ${this.getActivityIcon(activity.type)}
                </div>
                <div class="activity-content">
                    <p>${activity.description}</p>
                    <small>${new Date(activity.timestamp).toLocaleString()}</small>
                </div>
            </div>
        `).join('');
    }

    async loadUsersData() {
        try {
            const response = await fetch('/api/admin/users', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to load users data');
            }

            const data = await response.json();
            if (data.success) {
                this.renderUsersTable(data.users);
            }
        } catch (error) {
            console.error('Error loading users data:', error);
        }
    }

    renderUsersTable(users) {
        const tableBody = document.getElementById('usersTableBody');
        if (!tableBody) return;

        if (!users.length) {
            tableBody.innerHTML = '<tr><td colspan="7">No users found</td></tr>';
            return;
        }

        tableBody.innerHTML = users.map(user => `
            <tr>
                <td>${user.name}</td>
                <td>${user.email}</td>
                <td>${user.role}</td>
                <td>
                    <span class="status-badge ${user.verified ? 'verified' : 'unverified'}">
                        ${user.verified ? 'Verified' : 'Unverified'}
                    </span>
                </td>
                <td>${user.propertiesCount}</td>
                <td>${user.documentsCount}</td>
                <td>
                    <div class="user-actions">
                        <button class="action-button" onclick="adminPortal.editUser(${user.id})">
                            <svg viewBox="0 0 24 24"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
                        </button>
                        <button class="action-button" onclick="adminPortal.deleteUser(${user.id})">
                            <svg viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    async editUser(userId) {
        // Implementation for editing user
        console.log('Edit user:', userId);
    }

    async deleteUser(userId) {
        if (!confirm('Are you sure you want to delete this user?')) return;

        try {
            const response = await fetch(`/api/admin/users/${userId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to delete user');
            }

            await this.loadUsersData();
        } catch (error) {
            console.error('Error deleting user:', error);
        }
    }

    async loadPropertiesData() {
        try {
            const response = await fetch('/api/admin/properties', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to load properties data');
            }

            const data = await response.json();
            if (data.success) {
                this.renderProperties(data.properties);
            }
        } catch (error) {
            console.error('Error loading properties data:', error);
        }
    }

    renderProperties(properties) {
        const grid = document.getElementById('propertiesGrid');
        if (!grid) return;

        if (!properties.length) {
            grid.innerHTML = '<p>No properties found</p>';
            return;
        }

        grid.innerHTML = properties.map(property => `
            <div class="property-card">
                <div class="property-header">
                    <h3 class="property-title">${property.address}</h3>
                    <span class="property-status ${property.tenant ? 'status-occupied' : 'status-vacant'}">
                        ${property.tenant ? 'Occupied' : 'Vacant'}
                    </span>
                </div>
                <div class="property-details">
                    <div class="property-detail">
                        <svg viewBox="0 0 24 24" width="16" height="16">
                            <path d="M19 9.3V4h-3v2.6L12 3 2 12h3v8h5v-6h4v6h5v-8h3l-3-2.7zM10 10c0-1.1.9-2 2-2s2 .9 2 2h-4z"/>
                        </svg>
                        ${property.type}
                    </div>
                    <div class="property-detail">
                        <svg viewBox="0 0 24 24" width="16" height="16">
                            <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>
                        </svg>
                        ${property.tenant || 'No tenant'}
                    </div>
                    <div class="property-detail">
                        <svg viewBox="0 0 24 24" width="16" height="16">
                            <path d="M11.8 10.9c-2.27-.59-3-1.2-3-2.15 0-1.09 1.01-1.85 2.7-1.85 1.78 0 2.44.85 2.5 2.1h2.21c-.07-1.72-1.12-3.3-3.21-3.81V3h-3v2.16c-1.94.42-3.5 1.68-3.5 3.61 0 2.31 1.91 3.46 4.7 4.13 2.5.6 3 1.48 3 2.41 0 .69-.49 1.79-2.7 1.79-2.06 0-2.87-.92-2.98-2.1h-2.2c.12 2.19 1.76 3.42 3.68 3.83V21h3v-2.15c1.95-.37 3.5-1.5 3.5-3.55 0-2.84-2.43-3.81-4.7-4.4z"/>
                        </svg>
                        $${property.rent}/month
                    </div>
                </div>
                <div class="property-actions">
                    <button class="property-action" onclick="adminPortal.editProperty(${property.id})">
                        <svg viewBox="0 0 24 24"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
                    </button>
                    <button class="property-action" onclick="adminPortal.deleteProperty(${property.id})">
                        <svg viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                    </button>
                </div>
            </div>
        `).join('');
    }

    async loadMessagesData() {
        try {
            const response = await fetch('/api/admin/messages', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to load messages data');
            }

            const data = await response.json();
            if (data.success) {
                this.renderMessages(data.messages);
            }
        } catch (error) {
            console.error('Error loading messages data:', error);
        }
    }

    renderMessages(messages) {
        const list = document.getElementById('messagesList');
        if (!list) return;

        if (!messages.length) {
            list.innerHTML = '<p class="no-messages">No messages found</p>';
            return;
        }

        list.innerHTML = messages.map(message => `
            <div class="message-item" onclick="adminPortal.showMessage(${message.id})">
                <h3>${message.subject}</h3>
                <p>${message.preview}</p>
                <div class="message-meta">
                    <span>${message.sender}</span>
                    <span>${new Date(message.timestamp).toLocaleDateString()}</span>
                </div>
            </div>
        `).join('');
    }

    showMessage(id) {
        const content = document.getElementById('messageContent');
        if (!content) return;

        // In a real application, you would fetch the full message content
        content.innerHTML = `
            <div class="message-header">
                <h2>Message Title</h2>
                <p>From: sender@example.com</p>
                <p>Received: ${new Date().toLocaleString()}</p>
            </div>
            <div class="message-body">
                <p>Message content will be displayed here.</p>
            </div>
            <div class="message-actions">
                <button class="btn btn-primary" onclick="adminPortal.replyToMessage(${id})">Reply</button>
                <button class="btn btn-secondary" onclick="adminPortal.archiveMessage(${id})">Archive</button>
            </div>
        `;
    }

    getActivityIcon(type) {
        const icons = {
            user: '<svg viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>',
            property: '<svg viewBox="0 0 24 24"><path d="M12 3L1 9l4 2.18v6L12 21l7-3.82v-6l2-1.09V17h2V9L12 3zm6.82 6L12 12.72 5.18 9 12 5.28 18.82 9z"/></svg>',
            document: '<svg viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>',
            message: '<svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg>'
        };
        return icons[type] || icons.user;
    }
}

// Initialize admin portal when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.adminPortal = new AdminPortal();
}); 