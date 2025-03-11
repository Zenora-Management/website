// Portal Authentication and Data Loading
class PortalManager {
    constructor() {
        this.token = localStorage.getItem('token');
        this.userData = null;
        this.isAdmin = false;
    }

    async initialize() {
        if (!this.token) {
            window.location.href = '/auth/login.html';
            return;
        }

        try {
            const response = await fetch('/api/user/profile', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) {
                throw new Error('Authentication failed');
            }

            const data = await response.json();
            this.userData = data.user;
            this.isAdmin = this.userData.role === 'admin';
            
            // Update UI with user data
            this.updateUI();
            
            // Load page-specific data
            await this.loadPageData();
        } catch (error) {
            console.error('Portal initialization failed:', error);
            localStorage.removeItem('token');
            window.location.href = '/auth/login.html';
        }
    }

    updateUI() {
        // Update user name
        const userNameElement = document.getElementById('userName');
        if (userNameElement) {
            userNameElement.textContent = this.userData.name;
        }

        // Update navigation based on user role
        if (this.isAdmin) {
            const adminNav = document.createElement('a');
            adminNav.href = '/portal/admin/dashboard.html';
            adminNav.className = 'nav-item';
            adminNav.innerHTML = `
                <svg viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
                Admin Panel
            `;
            document.querySelector('.sidebar-nav').insertBefore(
                adminNav,
                document.querySelector('.sidebar-nav').lastElementChild
            );
        }
    }

    async loadPageData() {
        const currentPage = window.location.pathname.split('/').pop();
        
        switch (currentPage) {
            case 'dashboard.html':
                await this.loadDashboardData();
                break;
            case 'properties.html':
                await this.loadPropertiesData();
                break;
            case 'documents.html':
                await this.loadDocumentsData();
                break;
            case 'messages.html':
                await this.loadMessagesData();
                break;
            case 'settings.html':
                await this.loadSettingsData();
                break;
        }
    }

    async loadDashboardData() {
        try {
            const response = await fetch('/api/user/dashboard', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) throw new Error('Failed to load dashboard data');

            const data = await response.json();
            
            // Update property stats
            const propertyStats = document.getElementById('propertyStats');
            if (propertyStats) {
                propertyStats.innerHTML = `
                    <p>Total Properties: <strong>${data.properties.total}</strong></p>
                    <p>Active Tenants: <strong>${data.properties.activeTenants}</strong></p>
                    <p>Maintenance Requests: <strong>${data.properties.maintenanceRequests}</strong></p>
                `;
            }

            // Update financial stats
            const financialStats = document.getElementById('financialStats');
            if (financialStats) {
                financialStats.innerHTML = `
                    <p>Monthly Revenue: <strong>$${data.financial.monthlyRevenue}</strong></p>
                    <p>Next Payment Due: <strong>${data.financial.nextPaymentDue}</strong></p>
                    <p>Outstanding Balance: <strong>$${data.financial.outstandingBalance}</strong></p>
                `;
            }

            // Update recent updates
            const recentUpdates = document.getElementById('recentUpdates');
            if (recentUpdates && data.recentUpdates) {
                recentUpdates.innerHTML = data.recentUpdates.map(update => `
                    <div class="update-item">
                        <h4>${update.title}</h4>
                        <p>${update.description}</p>
                        <span class="date">${update.date}</span>
                    </div>
                `).join('');
            }
        } catch (error) {
            console.error('Error loading dashboard data:', error);
        }
    }

    async loadPropertiesData() {
        // Implementation for properties page
    }

    async loadDocumentsData() {
        // Implementation for documents page
    }

    async loadMessagesData() {
        // Implementation for messages page
    }

    async loadSettingsData() {
        // Implementation for settings page
    }

    logout() {
        localStorage.removeItem('token');
        localStorage.removeItem('rememberedEmail');
        localStorage.removeItem('rememberedPassword');
        window.location.href = '/auth/login.html';
    }
}

// Initialize portal
const portal = new PortalManager();
document.addEventListener('DOMContentLoaded', () => portal.initialize());

// Handle logout
document.querySelector('a[href="../auth/login.html"]').addEventListener('click', (e) => {
    e.preventDefault();
    portal.logout();
}); 