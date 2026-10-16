"""
nsys profiling plots.

Builds the stacked-bar (all profiles) and horizontal-bar (single profile)
Plotly charts, and the /profiles and /profile/{id} routes that render them.
"""

import logging

import plotly.graph_objects as go
import plotly.io as pio

from litestar import Request, Router, get
from litestar.datastructures import State
from litestar.response import Template

from auth import require_login, session_user_context
from config import Config
from mongodb import MongoDBService


def create_profiles_chart(profiles: list) -> str:
    """
    Create a stacked bar chart showing relative time for each range across profiles
    """
    if not profiles:
        return "<p style='text-align: center; color: #8b949e;'>No profiling data available</p>"

    # Get top ranges by average relative time across all profiles
    range_totals = {}
    for profile in profiles:
        for metric in profile.get('metrics', []):
            range_name = metric['range']
            rel_time = metric['relativeTime']
            if range_name == "simulate_pixels" or range_name == "run_simulation":
                continue
            if range_name not in range_totals:
                range_totals[range_name] = []
            range_totals[range_name].append(rel_time)

    # Calculate average and sort
    range_averages = {k: sum(v) / len(v) for k, v in range_totals.items()}
    top_ranges = sorted(range_averages.items(), key=lambda x: x[1], reverse=True)[:10]
    top_range_names = [r[0] for r in top_ranges]

    fig = go.Figure()

    # Create a bar for each range
    for range_name in top_range_names:
        x_labels = []
        y_values = []
        rel_times = []

        for profile in profiles:
            # Create label from timestamp and source file
            timestamp = profile.get('timestamp', '')
            if timestamp:
                label = timestamp.strftime('%Y-%m-%d %H:%M %Z') if hasattr(timestamp, 'strftime') else str(timestamp)[:16]
            else:
                label = str(profile.get('_id', ''))[:8]

            source = profile.get('source_file', '')
            if source:
                label = f"{label}<br>{source[:20]}"

            x_labels.append(label)

            for metric in profile.get('metrics', []):
                if metric['range'] == range_name:
                    tot_time = metric['totalTime'] / 1000.0
                    rel_time = metric['relativeTime']
                    break
            y_values.append(tot_time)
            rel_times.append(rel_time)

        fig.add_trace(go.Bar(
            name=range_name,
            x=x_labels,
            y=y_values,
            customdata=rel_times,
            text=[f"{range_name}<br>{v:.2f}s" for v in y_values],
            textposition='inside',
            textfont=dict(size=11),
            hovertemplate='<b>%{fullData.name}</b><br>' +
                          'Total: %{y:.2f}s<br>' +
                          'Relative: %{customdata:.1f}%<extra></extra>'
        ))

    fig.update_layout(
        barmode='stack',
        title='Profiling Data: Total Time by Range',
        xaxis_title='Profile Run',
        yaxis_title='Total Time (s)',
        template='plotly_dark',
        height=600,
        showlegend=True,
        legend=dict(
            orientation="v",
            yanchor="top",
            y=1,
            xanchor="left",
            x=1.02
        ),
        margin=dict(r=200),
        plot_bgcolor='#0d1117',
        paper_bgcolor='#0d1117',
        font=dict(color='#c9d1d9')
    )

    return pio.to_html(fig, include_plotlyjs='cdn', div_id='profiles-chart')


def create_single_profile_chart(profile: dict) -> str:
    """
    Create a horizontal bar chart for a single profile showing relative times
    """
    metrics = profile.get('metrics', [])
    if not metrics:
        return "<p style='text-align: center; color: #8b949e;'>No metrics available</p>"

    # Sort by relative time descending
    sorted_metrics = sorted(metrics, key=lambda x: x['relativeTime'], reverse=True)

    # Take top 20 for readability
    top_metrics = sorted_metrics[:20]

    ranges = [m['range'] for m in top_metrics]
    rel_times = [m['relativeTime'] for m in top_metrics]
    total_times = [m['totalTime'] for m in top_metrics]

    fig = go.Figure()

    fig.add_trace(go.Bar(
        y=ranges,
        x=rel_times,
        orientation='h',
        text=[f"{rt:.1f}%" for rt in rel_times],
        textposition='outside',
        marker=dict(
            color=rel_times,
            colorscale='Blues',
            showscale=True,
            colorbar=dict(title="Relative<br>Time (%)")
        ),
        hovertemplate='<b>%{y}</b><br>Relative: %{x:.2f}%<br>Total: %{customdata:.2f}ms<extra></extra>',
        cliponaxis=False,
        customdata=total_times
    ))

    source_file = profile.get('source_file', 'Unknown')
    timestamp = profile.get('timestamp', '')
    if hasattr(timestamp, 'strftime'):
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')
    else:
        timestamp_str = str(timestamp)

    fig.update_layout(
        title=f'Profile: {source_file}<br><sub>{timestamp_str}</sub>',
        xaxis_title='Relative Time (%)',
        yaxis_title='NVTX Range',
        template='plotly_dark',
        height=max(600, len(top_metrics) * 25),
        plot_bgcolor='#0d1117',
        paper_bgcolor='#0d1117',
        font=dict(color='#c9d1d9'),
        yaxis=dict(autorange='reversed')
    )

    return pio.to_html(fig, include_plotlyjs='cdn', div_id='profile-chart')


@get("/profiles", guards=[require_login])
async def profiles_list(request: Request, state: State) -> Template:
    """
    Page displaying all profiling runs with stacked bar chart
    """
    config: Config = state.config
    # Check if MongoDB is connected
    if not hasattr(state, 'mongo_service') or state.mongo_service is None:
        return Template(
            template_name="mongo_error.html",
            context={
                "error_type": "MongoDB Connection Failed",
                "mongodb_url": config.mongodb.url,
                "mongodb_db": config.mongodb.db,
                "request": request,
                **session_user_context(request),
            }
        )

    try:
        mongo_service: MongoDBService = state.mongo_service
        profiles = await mongo_service.get_profiles(limit=50)

        # Create stacked bar chart
        chart_html = create_profiles_chart(profiles)

        return Template(
            template_name="profiles.html",
            context={
                "profiles": profiles,
                "chart_html": chart_html,
                "request": request,
                **session_user_context(request),
            }
        )
    except Exception as e:
        logging.error(f"Error building profiles page: {e}")
        return Template(
            template_name="mongo_error.html",
            context={
                "error_type": "MongoDB Error",
                "mongodb_url": config.mongodb.url,
                "mongodb_db": config.mongodb.db,
                "error_message": str(e),
                "request": request,
                **session_user_context(request),
            }
        )


@get("/profile/{profile_id:str}", guards=[require_login])
async def profile_detail(request: Request, state: State, profile_id: str) -> Template:
    """
    Detailed view of a single profile with individual chart
    """
    mongo_service: MongoDBService = state.mongo_service
    profile = await mongo_service.get_profile_by_id(profile_id)

    if not profile:
        return Template(
            template_name="http_error.html",
            context={
                "status_code": 404,
                "error_title": "Profile Not Found",
                "error_message": "The profile you're looking for doesn't exist.",
                "request_path": f"/profile/{profile_id}",
                "request": request,
                **session_user_context(request),
            },
            status_code=404
        )

    # Create individual profile chart
    chart_html = create_single_profile_chart(profile)

    return Template(
        template_name="profile_detail.html",
        context={
            "profile": profile,
            "chart_html": chart_html,
            "request": request,
            **session_user_context(request),
        }
    )


profiles_router = Router(path="/", route_handlers=[profiles_list, profile_detail])
