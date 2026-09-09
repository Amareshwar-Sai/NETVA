"""Report route — PDF download."""
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from backend.api.state import app_state
import traceback

router = APIRouter()

@router.get("/report/pdf")
async def download_report():
    """Generate and return a full NETVA analysis PDF report."""
    if not app_state.ready:
        raise HTTPException(425, "Pipeline not complete. Run a scan first.")
    try:
        from backend.reports.pdf_generator import generate_pdf_report
        r = app_state.current_run
        pdf_bytes = generate_pdf_report(
            network=r.network, G=r.G, amc=r.amc, policy=r.policy, paths=r.paths)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "inline; filename=NETVA_Report.pdf"})
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, f"Report generation failed: {str(e)}")