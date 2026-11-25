export const clampSize = (value, min, max) => Math.min(Math.max(Math.round(value), min), Math.max(min, max));

export function installSplitters(load, save) {
  const vault = document.querySelector('#vault-view');
  if (!vault) return;
  const panels = {
    groups: { sign: 1, min: 170, max: () => vault.clientWidth * 0.36 },
    detail: { sign: -1, min: 240, max: () => vault.clientWidth * 0.48 },
  };
  const size = id => document.getElementById(id)?.getBoundingClientRect().width ?? 0;
  const layout = {};
  for (const handle of document.querySelectorAll('[data-split]')) {
    const id = handle.dataset.split;
    const panel = panels[id];
    if (!panel) continue;
    const { sign, min, max } = panel;
    const property = `--${id}-size`;
    if (Number.isFinite(load?.[id]) && load[id] > 0) {
      layout[id] = Math.round(load[id]);
      vault.style.setProperty(property, `${layout[id]}px`);
    }
    const updateAria = () => {
      const upper = Math.floor(Math.max(min, max()));
      handle.setAttribute('aria-valuemin', min);
      handle.setAttribute('aria-valuemax', upper);
      handle.setAttribute('aria-valuenow', clampSize(size(id), min, upper));
    };
    const apply = value => {
      layout[id] = clampSize(value, min, Math.floor(max()));
      vault.style.setProperty(property, `${layout[id]}px`);
      updateAria();
    };
    let drag = null;
    handle.addEventListener('pointerdown', event => {
      if (event.button !== 0 || drag) return;
      event.preventDefault();
      handle.focus();
      drag = { id: event.pointerId, start: event.clientX, size: size(id) };
      handle.setPointerCapture(event.pointerId);
      handle.classList.add('dragging');
      document.body.style.setProperty('--resize-cursor', 'col-resize');
      document.body.classList.add('resizing');
    });
    handle.addEventListener('pointermove', event => {
      if (drag?.id === event.pointerId) apply(drag.size + sign * (event.clientX - drag.start));
    });
    const finish = event => {
      if (drag?.id !== event.pointerId) return;
      drag = null;
      handle.classList.remove('dragging');
      document.body.classList.remove('resizing');
      save(layout);
    };
    handle.addEventListener('pointerup', finish);
    handle.addEventListener('pointercancel', finish);
    handle.addEventListener('lostpointercapture', finish);
    const reset = () => {
      delete layout[id];
      vault.style.removeProperty(property);
      updateAria();
      save(layout);
    };
    handle.addEventListener('dblclick', reset);
    handle.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End', 'Enter'].includes(event.key)) return;
      event.preventDefault();
      if (event.key === 'Enter') return reset();
      const step = (event.key === 'ArrowLeft' ? -1 : 1) * sign * (event.shiftKey ? 40 : 12);
      apply(event.key === 'Home' ? min : event.key === 'End' ? max() : size(id) + step);
      save(layout);
    });
    new ResizeObserver(updateAria).observe(handle);
  }
}
