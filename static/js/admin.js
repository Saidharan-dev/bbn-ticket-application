// Admin Dashboard JavaScript
let selectedTicketId = null;
let allReceivedTickets = [];
let allResolvedTickets = [];

// Menu navigation
// menu items that switch views have a data-view attribute
document.querySelectorAll('.menu-item[data-view]').forEach(item => {
    item.addEventListener('click', function() {
        const view = this.getAttribute('data-view');
        switchView(view);
        
        document.querySelectorAll('.menu-item[data-view]').forEach(m => m.classList.remove('active'));
        this.classList.add('active');
    });
});

// Company filter listener
document.getElementById('companyFilter')?.addEventListener('change', function() {
    const currentView = document.querySelector('.menu-item.active')?.getAttribute('data-view');
    if (currentView === 'received') {
        displayFilteredTickets(allReceivedTickets, 'received-tickets', 'received');
    } else if (currentView === 'resolved') {
        displayFilteredTickets(allResolvedTickets, 'resolved-tickets', 'resolved');
    }
});

// Priority filter listener
document.getElementById('priorityFilter')?.addEventListener('change', function() {
    const currentView = document.querySelector('.menu-item.active')?.getAttribute('data-view');
    if (currentView === 'received') {
        displayFilteredTickets(allReceivedTickets, 'received-tickets', 'received');
    } else if (currentView === 'resolved') {
        displayFilteredTickets(allResolvedTickets, 'resolved-tickets', 'resolved');
    }
});

function switchView(view) {
    document.querySelectorAll('.view-section').forEach(section => {
        section.classList.remove('active');
    });
    
    const viewElement = document.getElementById(view + '-view');
    if (viewElement) {
        viewElement.classList.add('active');
    }
    
    if (view === 'received') {
        loadReceivedTickets();
    } else if (view === 'resolved') {
        loadResolvedTickets();
    }
}

// Load tickets
async function loadReceivedTickets() {
    try {
        const response = await fetch('/api/received-tickets');
        allReceivedTickets = await response.json();
        displayFilteredTickets(allReceivedTickets, 'received-tickets', 'received');
    } catch (error) {
        console.error('Error loading received tickets:', error);
    }
}

async function loadResolvedTickets() {
    try {
        const response = await fetch('/api/resolved-tickets');
        allResolvedTickets = await response.json();
        displayFilteredTickets(allResolvedTickets, 'resolved-tickets', 'resolved');
    } catch (error) {
        console.error('Error loading resolved tickets:', error);
    }
}

// Load companies to populate filter
async function loadCompanies() {
    try {
        const res = await fetch('/api/companies');
        if (!res.ok) return;
        const companies = await res.json();
        const select = document.getElementById('companyFilter');
        if (!select) return;
        // clear existing except 'All Companies' placeholder
        select.innerHTML = '';
        const allOpt = document.createElement('option');
        allOpt.value = '';
        allOpt.textContent = 'All Companies';
        select.appendChild(allOpt);
        companies.forEach(c => {
            const opt = document.createElement('option');
            opt.value = c.username;
            opt.textContent = c.company_name || c.username;
            select.appendChild(opt);
        });
    } catch (err) {
        console.error('Error loading companies:', err);
    }
}

// Add Company UI handlers
document.getElementById('btnAddCompany')?.addEventListener('click', function() {
    document.getElementById('addCompanyModal')?.classList.add('show');
});

document.getElementById('addCompanyForm')?.addEventListener('submit', async function(e) {
    e.preventDefault();
    const password = document.getElementById('newPassword').value;
    const company_name = document.getElementById('newCompanyName').value.trim();
    const msg = document.getElementById('add-company-message');
    try {
        const res = await fetch('/api/companies', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({company_name, password})
        });
        const data = await res.json();
        if (res.ok) {
            msg.textContent = 'Company added successfully. Username: ' + (data.username || '') ;
            msg.className = 'message success';
            msg.style.display = 'block';
            // refresh company list
            await loadCompanies();
            setTimeout(() => {
                document.getElementById('addCompanyModal')?.classList.remove('show');
                msg.style.display = 'none';
                document.getElementById('addCompanyForm').reset();
            }, 1200);
        } else {
            msg.textContent = data.error || 'Error adding company.';
            msg.className = 'message error';
            msg.style.display = 'block';
        }
    } catch (err) {
        console.error('Error adding company:', err);
        msg.textContent = 'Error adding company.';
        msg.className = 'message error';
        msg.style.display = 'block';
    }
});

// Apply company filter to tickets
function getFilteredTickets(tickets) {
    const companyFilter = document.getElementById('companyFilter')?.value || '';
    const priorityFilter = document.getElementById('priorityFilter')?.value || '';

    let result = tickets;

    if (companyFilter) {
        result = result.filter(ticket => (ticket.company || ticket.client) === companyFilter);
    }

    if (priorityFilter) {
        result = result.filter(ticket => (ticket.priority || 'Medium') === priorityFilter);
    }

    return result;
}

function displayFilteredTickets(tickets, containerId, type) {
    const filteredTickets = getFilteredTickets(tickets);
    displayTickets(filteredTickets, containerId, type);
}

function displayTickets(tickets, containerId, type) {
    const container = document.getElementById(containerId);
    
    if (tickets.length === 0) {
        container.innerHTML = '<p class="loading">No tickets found.</p>';
        return;
    }
    
    container.innerHTML = tickets.map(ticket => `
        <div class="ticket-card" onclick="viewTicket(${ticket.id})">
            <div class="ticket-header">
                <div class="ticket-id">Ticket #${ticket.id} - ${ticket.company_name || ticket.client}</div>
                <div class="ticket-priority">Priority: ${ticket.priority || 'Medium'}</div>
                <div class="ticket-raised">Raised by: ${ticket.raised_by || '—'} (${ticket.designation || '—'})</div>
                <span class="ticket-status ${ticket.status === 'pending' ? 'status-pending' : 'status-resolved'}">
                    ${ticket.status === 'pending' ? 'Pending' : 'Resolved'}
                </span>
            </div>
            <div class="ticket-problem">${ticket.problem.substring(0, 100)}...</div>
            <div class="ticket-client">Company: ${ticket.company_name || ticket.client}</div>
            <div class="ticket-date">Created: ${new Date(ticket.created_at).toLocaleDateString()}</div>
            ${type === 'received' ? `
            <div class="ticket-actions">
                <button class="btn-solution" onclick="openSolutionModal(event, ${ticket.id})">Write Solution</button>
            </div>
            ` : ''}
        </div>
    `).join('');
}

// View ticket details
function viewTicket(ticketId) {
    selectedTicketId = ticketId;
    
    fetch(`/api/tickets/${ticketId}`)
        .then(response => response.json())
        .then(ticket => {
            let detailsHTML = `
                <div class="detail-row">
                    <div class="detail-label">Ticket ID:</div>
                    <div class="detail-value">#${ticket.id}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Company:</div>
                    <div class="detail-value">${ticket.company_name || ticket.client}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Priority:</div>
                    <div class="detail-value">${ticket.priority || 'Medium'}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Raised By:</div>
                    <div class="detail-value">${ticket.raised_by || '—'} (${ticket.designation || '—'})</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Status:</div>
                    <div class="detail-value">
                        <span class="ticket-status ${ticket.status === 'pending' ? 'status-pending' : 'status-resolved'}">
                            ${ticket.status === 'pending' ? 'Pending' : 'Resolved'}
                        </span>
                    </div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Problem:</div>
                    <div class="detail-value">${ticket.problem}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Created:</div>
                    <div class="detail-value">${new Date(ticket.created_at).toLocaleString()}</div>
                </div>
                ${ticket.attachments && ticket.attachments.length > 0 ? `
                <div class="detail-row">
                    <div class="detail-label">Attachments:</div>
                    <div class="detail-value">${ticket.attachments.join(', ')}</div>
                </div>
                ` : ''}
                ${ticket.solution ? `
                <div class="detail-row">
                    <div class="detail-label">Solution:</div>
                    <div class="detail-value">
                        <div class="solution-box">${ticket.solution}</div>
                        <div style="font-size: 12px; color: #999;">
                            Resolved: ${new Date(ticket.solution_date).toLocaleString()}
                        </div>
                    </div>
                </div>
                ` : ''}
            `;
            
            document.getElementById('ticketDetails').innerHTML = detailsHTML;
            document.getElementById('ticketModal').classList.add('show');
        })
        .catch(error => console.error('Error loading ticket:', error));
}

// Open solution modal
function openSolutionModal(event, ticketId) {
    event.stopPropagation();
    selectedTicketId = ticketId;
    document.getElementById('solutionModal').classList.add('show');
}

// Modal close
document.querySelectorAll('.close').forEach(closeBtn => {
    closeBtn.addEventListener('click', function() {
        this.closest('.modal, .chat-modal-fullscreen').classList.remove('show');
    });
});

// Submit solution form
document.getElementById('solutionForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const solution = document.getElementById('solutionText').value;
    
    try {
        const response = await fetch(`/api/tickets/${selectedTicketId}/solution`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ solution })
        });
        
        if (response.ok) {
            const message = document.getElementById('solution-message');
            message.textContent = 'Solution sent successfully!';
            message.classList.remove('error');
            message.classList.add('success');
            message.style.display = 'block';
            
            document.getElementById('solutionForm').reset();
            
            setTimeout(() => {
                document.getElementById('solutionModal').classList.remove('show');
                message.style.display = 'none';
                loadReceivedTickets();
            }, 1500);
        }
    } catch (error) {
        console.error('Error submitting solution:', error);
        const message = document.getElementById('solution-message');
        message.textContent = 'Error submitting solution!';
        message.classList.remove('success');
        message.classList.add('error');
        message.style.display = 'block';
    }
});

// Initial load
loadCompanies();
loadReceivedTickets();

// Chat assistant handlers - fresh ephemeral chat each session (no localStorage persistence)
let currentChatMessages = [];

document.getElementById('btnChat')?.addEventListener('click', function() {
    document.getElementById('chatModal')?.classList.add('show');
    // Fresh chat each time modal opens
    currentChatMessages = [];
    document.getElementById('chatTitle').textContent = 'AI Assistant';
    document.getElementById('chatMessages').innerHTML = '';
    document.getElementById('chatInput').value = '';
});

document.querySelectorAll('#chatModal .close').forEach(closeBtn => {
    closeBtn.addEventListener('click', function() {
        this.closest('.modal, .chat-modal-fullscreen').classList.remove('show');
        // Clear chat on modal close
        currentChatMessages = [];
        document.getElementById('chatMessages').innerHTML = '';
        document.getElementById('chatInput').value = '';
    });
});

function appendChatMessage(role, text) {
    const container = document.getElementById('chatMessages');
    if (!container) return;
    const el = document.createElement('div');
    el.className = 'chat-line ' + (role === 'assistant' ? 'assistant' : 'user');
    el.textContent = text;
    container.appendChild(el);
    container.scrollTop = container.scrollHeight;

    // Keep only in memory for this session
    currentChatMessages.push({ role, text });
}

document.getElementById('chatForm')?.addEventListener('submit', async function(e) {
    e.preventDefault();
    const input = document.getElementById('chatInput');
    const status = document.getElementById('chat-status');
    if (!input || !input.value.trim()) return;
    const msg = input.value.trim();
    appendChatMessage('user', msg);
    input.value = '';
    status.style.display = 'block';
    status.textContent = 'Thinking...';

    try {
        const res = await fetch('/api/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message: msg})
        });

        const data = await res.json();
        if (res.ok && data.reply) {
            appendChatMessage('assistant', data.reply);
            status.style.display = 'none';
        } else {
            appendChatMessage('assistant', data.error || 'No response from assistant');
            status.style.display = 'none';
        }
    } catch (err) {
        console.error('Chat error:', err);
        appendChatMessage('assistant', 'Error contacting assistant');
        status.style.display = 'none';
    }
});
